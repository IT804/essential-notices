require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs/promises');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1);
const port = Number(process.env.PORT || 3000);
const pool = mysql.createPool({host:process.env.DB_HOST,port:Number(process.env.DB_PORT||3306),user:process.env.DB_USER,password:process.env.DB_PASSWORD,database:process.env.DB_NAME,ssl:process.env.DB_SSL==='true'?{minVersion:'TLSv1.2'}:undefined,waitForConnections:true,connectionLimit:10,charset:'utf8mb4',timezone:'Z'});
async function ensureFeatureTables(){
  // Older Render databases may predate photo support even though announcement
  // listing now counts photos with a subquery. Keep startup self-healing so an
  // un-applied schema.sql migration cannot break the public feed.
  await pool.execute("CREATE TABLE IF NOT EXISTS announcement_photos (announcement_id BIGINT UNSIGNED NOT NULL,photo_index TINYINT UNSIGNED NOT NULL,mime_type VARCHAR(32) NOT NULL,photo_data MEDIUMBLOB NOT NULL,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY (announcement_id,photo_index)) ENGINE=InnoDB");
  await pool.execute("CREATE TABLE IF NOT EXISTS blood_donors (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,region VARCHAR(100) NOT NULL,blood_type ENUM('O+','O-','A+','A-','B+','B-','AB+','AB-') NOT NULL,contact_name_enc TEXT NULL,contact_phone_enc TEXT NOT NULL,status ENUM('pending','verified','rejected') NOT NULL DEFAULT 'pending',created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,INDEX idx_donors_public (status,blood_type,region)) ENGINE=InnoDB");
  await pool.execute("CREATE TABLE IF NOT EXISTS announcement_controls (announcement_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,token_hash CHAR(64) NOT NULL,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,CONSTRAINT fk_control_announcement FOREIGN KEY (announcement_id) REFERENCES announcements(id) ON DELETE CASCADE) ENGINE=InnoDB");
  await pool.execute("CREATE TABLE IF NOT EXISTS announcement_feedback (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,announcement_id BIGINT UNSIGNED NOT NULL,kind ENUM('tip','report') NOT NULL,reason VARCHAR(40) NULL,details TEXT NOT NULL,contact_name_enc TEXT NULL,contact_phone_enc TEXT NULL,status ENUM('pending','reviewed','dismissed') NOT NULL DEFAULT 'pending',created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,INDEX idx_feedback_queue (status,kind,created_at),INDEX idx_feedback_announcement (announcement_id)) ENGINE=InnoDB");
  await pool.execute("CREATE TABLE IF NOT EXISTS demo_data_state (state_key VARCHAR(32) NOT NULL PRIMARY KEY,state_value VARCHAR(32) NOT NULL,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) ENGINE=InnoDB");
}
const featureTablesReady=ensureFeatureTables();featureTablesReady.catch(error=>console.error(`Supplemental database setup failed: ${error.code||error.message}`));
const demoDataReady=featureTablesReady.then(()=>seedDemoSamples());demoDataReady.catch(error=>console.error(`Demo data setup failed: ${error.code||error.message}`));

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false, crossOriginEmbedderPolicy:false}));
app.use(express.json({limit:'9mb'}));
app.use(express.urlencoded({extended:false,limit:'100kb'}));
app.use((req,res,next)=>{const raw=req.headers.cookie||'';req.cookies=Object.fromEntries(raw.split(';').map(part=>part.trim()).filter(Boolean).map(part=>{const i=part.indexOf('=');return [decodeURIComponent(part.slice(0,i)),decodeURIComponent(part.slice(i+1))]}));next()});
app.use('/api/auth', rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:true,legacyHeaders:false}));
app.use('/api/announcements', rateLimit({windowMs:60*60*1000,limit:12,standardHeaders:true,legacyHeaders:false}));
app.use('/api/donors',rateLimit({windowMs:60*60*1000,limit:5,standardHeaders:true,legacyHeaders:false}));
app.use('/api/my-announcements',rateLimit({windowMs:60*60*1000,limit:8,standardHeaders:true,legacyHeaders:false}));

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const MAX_PHOTO_BYTES = 3 * 1024 * 1024;
const PHOTO_MIME_TYPES = new Set(['image/jpeg','image/png','image/webp']);
function decodePhoto(photo) {
  if (!photo || typeof photo.dataUrl !== 'string' || photo.dataUrl.length > 4.1 * MAX_PHOTO_BYTES) return null;
  const match = /^data:(image\/jpeg|image\/png|image\/webp);base64,([A-Za-z0-9+/]+={0,2})$/.exec(photo.dataUrl);
  if (!match || !PHOTO_MIME_TYPES.has(match[1])) return null;
  const data = Buffer.from(match[2], 'base64');
  if (!data.length || data.length > MAX_PHOTO_BYTES || data.toString('base64') !== match[2]) return null;
  const jpeg = match[1] === 'image/jpeg' && data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff;
  const png = match[1] === 'image/png' && data.subarray(0,8).equals(Buffer.from([0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]));
  const webp = match[1] === 'image/webp' && data.toString('ascii',0,4) === 'RIFF' && data.toString('ascii',8,12) === 'WEBP';
  return jpeg || png || webp ? { mimeType: match[1], data } : null;
}
function encrypt(value) {
  if (!value) return null;
  const keyHex = process.env.PII_ENCRYPTION_KEY || '';
  if (!/^[a-f0-9]{64}$/i.test(keyHex)) {
    const error = new Error('PII_ENCRYPTION_KEY must be 64 hex characters');
    error.code = 'PII_ENCRYPTION_KEY_NOT_CONFIGURED';
    throw error;
  }
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(keyHex,'hex'), iv);
  const encrypted = Buffer.concat([cipher.update(value,'utf8'),cipher.final()]);
  return [iv.toString('hex'),cipher.getAuthTag().toString('hex'),encrypted.toString('hex')].join(':');
}
function decrypt(value) {
  if (!value) return null;
  const [iv,tag,data] = value.split(':');
  const decipher = crypto.createDecipheriv('aes-256-gcm',Buffer.from(process.env.PII_ENCRYPTION_KEY,'hex'),Buffer.from(iv,'hex'));
  decipher.setAuthTag(Buffer.from(tag,'hex'));
  return Buffer.concat([decipher.update(Buffer.from(data,'hex')),decipher.final()]).toString('utf8');
}
function safeAnnouncement(row, admin=false) {
  const item={id:row.id,type:row.type,title:row.title,details:row.details,region:row.region,bloodType:row.blood_type,status:row.status,createdAt:row.created_at};
  if(admin){ try{item.contactName=decrypt(row.contact_name_enc);item.contactPhone=decrypt(row.contact_phone_enc)}catch{item.contactName=null;item.contactPhone=null} }
  const photoCount = Math.max(0, Math.min(2, Number(row.photo_count || 0)));
  item.photos = Array.from({length:photoCount},(_,index)=>`${admin?'/api/admin/photos':'/api/photos'}/${row.id}/${index+1}`);
  // Public markers deliberately use coarse city-level coordinates only.
  if(row.latitude && row.longitude && (admin || row.status==='verified')) item.location={lat:Math.round(Number(row.latitude)*10)/10,lng:Math.round(Number(row.longitude)*10)/10};
  return item;
}
function validPhone(value){return /^\+[1-9]\d{7,14}$/.test(value||'')}
function isAdminPhone(value){return (process.env.ADMIN_PHONE||'').split(',').map(phone=>phone.trim()).filter(Boolean).includes(value)}
function validCoords(lat,lng){const emptyLat=lat==null||lat==='',emptyLng=lng==null||lng==='';if(emptyLat&&emptyLng)return true;if(emptyLat||emptyLng)return false;return Number.isFinite(Number(lat))&&Number.isFinite(Number(lng))&&Math.abs(Number(lat))<=90&&Math.abs(Number(lng))<=180}
async function seedDemoSamples(){
  const conn=await pool.getConnection();
  try{
    await conn.beginTransaction();
    const [existingAnnouncements]=await conn.execute("SELECT type,title,status FROM announcements WHERE title LIKE ?",['[آزمایشی] غیرواقعی:%']);
    const [existingDonors]=await conn.execute("SELECT region,status FROM blood_donors WHERE region LIKE ?",['نمونه آزمایشی · %']);
    const [approvalRows]=await conn.execute("SELECT state_value FROM demo_data_state WHERE state_key='approved_v2'");
    const approvalRecorded=approvalRows[0]?.state_value==='yes';
    const announcementNumbers={blood:new Set(),missing:new Set(),found:new Set()};
    for(const row of existingAnnouncements){
      const match=row.title.match(/· نمونه (\d+)$/u);
      if(match&&announcementNumbers[row.type])announcementNumbers[row.type].add(Number(match[1]));
    }
    // Approval of the demo set is reflected by verified demo rows. Carry that
    // approval forward to any stranded pending samples when a deploy repairs
    // an incomplete set; never change rejected or resolved notices.
    const announcementsAlreadyApproved=approvalRecorded||existingAnnouncements.some(row=>row.status==='verified');
    const donorsAlreadyApproved=approvalRecorded||existingDonors.some(row=>row.status==='verified');
    const needsSamples=Object.values(announcementNumbers).some(numbers=>numbers.size<20);
    const car=needsSamples?await fs.readFile(path.join(__dirname,'sample-car.png')):null;
    const person=needsSamples?await fs.readFile(path.join(__dirname,'sample-person.png')):null;
    const groups=['O+','A+','B+','AB+','O-','A-','B-','AB-'];
    const regions=['کابل','هرات','مزار شریف','قندهار','جلال‌آباد'];
    for(let i=0;i<20;i++){
      const samples=[
        {type:'blood',blood:groups[i%groups.length],title:`[آزمایشی] غیرواقعی: درخواست خون ${groups[i%groups.length]} · نمونه ${String(i+1).padStart(2,'0')}`},
        {type:'missing',title:`[آزمایشی] غیرواقعی: اعلان فرد یا شیء گم‌شده · نمونه ${String(i+1).padStart(2,'0')}`,photo:i%5===4?car:person,mime:i%5===4?'image/png':'image/png'},
        {type:'found',title:`[آزمایشی] غیرواقعی: اعلان فرد یا شیء پیدا‌شده · نمونه ${String(i+1).padStart(2,'0')}`,photo:i%5===4?car:person,mime:'image/png'}
      ];
      for(const sample of samples){
        if(announcementNumbers[sample.type].has(i+1))continue;
        const status=announcementsAlreadyApproved?'verified':'pending';
        const [inserted]=await conn.execute('INSERT INTO announcements(type,title,details,region,blood_type,status) VALUES(?,?,?,?,?,?)',[sample.type,sample.title,'این دادهٔ آزمایشی و کاملاً غیرواقعی فقط برای نمایش و بررسی سامانه است. با آن تماس نگیرید و براساس آن اقدام نکنید.',`نمونه آزمایشی · ${regions[i%regions.length]}`,sample.blood||null,status]);
        if(sample.photo)await conn.execute('INSERT INTO announcement_photos(announcement_id,photo_index,mime_type,photo_data) VALUES(?,1,?,?)',[inserted.insertId,sample.mime,sample.photo]);
      }
    }
    for(let i=existingDonors.length;i<20;i++)await conn.execute('INSERT INTO blood_donors(region,blood_type,contact_name_enc,contact_phone_enc,status) VALUES(?,?,?,?,?)',[`نمونه آزمایشی · ${regions[i%regions.length]}`,groups[i%groups.length],encrypt('نمونهٔ ساختگی، نه اهداکنندهٔ واقعی'),encrypt('نمونهٔ آزمایشی است؛ شمارهٔ واقعی ندارد'),donorsAlreadyApproved?'verified':'pending']);
    // Migrate a previous bulk approval once, including any demo-only rows that
    // were left rejected. A saved marker prevents later admin rejections from
    // being undone by normal restarts or future deployments.
    if(!approvalRecorded&&(announcementsAlreadyApproved||donorsAlreadyApproved)){
      await conn.execute("UPDATE announcements SET status='verified' WHERE status IN ('pending','rejected','resolved') AND title LIKE ?",['[آزمایشی] غیرواقعی:%']);
      await conn.execute("UPDATE blood_donors SET status='verified' WHERE status IN ('pending','rejected') AND region LIKE ?",['نمونه آزمایشی · %']);
      await conn.execute("INSERT INTO demo_data_state(state_key,state_value) VALUES('approved_v2','yes') ON DUPLICATE KEY UPDATE state_value='yes'");
    }
    await conn.commit();
    console.log('Ensured 20 clearly labeled demo entries per announcement category and donor list.');
  }catch(error){await conn.rollback().catch(()=>{});throw error}finally{conn.release()}
}
function decodeBase32(value){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized=String(value||'').replace(/=+$/,'').toUpperCase();
  if(!/^[A-Z2-7]{32,}$/.test(normalized)) return null;
  let bits=0,buffer=0;const bytes=[];
  for(const character of normalized){
    const digit=alphabet.indexOf(character);if(digit<0)return null;
    buffer=(buffer<<5)|digit;bits+=5;
    if(bits>=8){bits-=8;bytes.push((buffer>>bits)&255)}
  }
  return Buffer.from(bytes);
}
function matchingTotpStep(code,secret,now=Math.floor(Date.now()/1000)){
  if(!/^\d{6}$/.test(String(code||'')))return null;
  const key=decodeBase32(secret);if(!key)return null;
  const current=Math.floor(now/30),candidate=Buffer.from(String(code));
  for(const step of [current-1,current,current+1]){
    const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(step));
    const digest=crypto.createHmac('sha1',key).update(counter).digest();
    const offset=digest[digest.length-1]&0x0f;
    const binary=((digest[offset]&0x7f)<<24)|(digest[offset+1]<<16)|(digest[offset+2]<<8)|digest[offset+3];
    const expected=Buffer.from(String(binary%1_000_000).padStart(6,'0'));
    if(crypto.timingSafeEqual(candidate,expected))return step;
  }
  return null;
}

async function adminAuth(req,res,next){
  try{
    const token=req.cookies?.admin_session || req.get('authorization')?.replace(/^Bearer\s+/i,'');
    if(!token) return res.status(401).json({error:'AUTH_REQUIRED'});
    const [rows]=await pool.execute('SELECT phone FROM admin_sessions WHERE token_hash=? AND expires_at>UTC_TIMESTAMP()',[sha(token)]);
    if(!rows.length || !isAdminPhone(rows[0].phone)) return res.status(401).json({error:'AUTH_REQUIRED'});
    req.admin={phone:rows[0].phone}; next();
  }catch(e){next(e)}
}

app.get('/api/config',(req,res)=>res.json({googleMapsApiKey:process.env.GOOGLE_MAPS_API_KEY||''}));
app.get('/api/announcements',async(req,res,next)=>{
  try{
    await featureTablesReady;
    const where=["a.status='verified'"], values=[];
    const types=['blood','missing','found'];
    if(types.includes(req.query.type)){where.push('a.type=?');values.push(req.query.type)}
    if(typeof req.query.region==='string'&&req.query.region.length<=100){where.push('a.region LIKE ?');values.push(`%${req.query.region}%`)}
    if(['O+','O-','A+','A-','B+','B-','AB+','AB-'].includes(req.query.bloodType)){where.push('a.blood_type=?');values.push(req.query.bloodType)}
    if(typeof req.query.search==='string'&&req.query.search.trim().length<=120){const query=`%${req.query.search.trim()}%`;where.push('(a.title LIKE ? OR a.details LIKE ? OR a.region LIKE ?)');values.push(query,query,query)}
    const page=Math.max(1,Math.min(100000,Number.parseInt(req.query.page,10)||1));
    const limit=Math.max(1,Math.min(15,Number.parseInt(req.query.limit,10)||12));
    const sort=req.query.sort==='oldest'?'ASC':'DESC';
    const [countRows]=await pool.execute(`SELECT COUNT(*) AS total FROM announcements a WHERE ${where.join(' AND ')}`,values);
    const offset=(page-1)*limit;
    // TiDB/MySQL permit bound values for LIMIT in most configurations, but
    // interpolating these bounded integers avoids prepared LIMIT parser errors.
    const [rows]=await pool.execute(`SELECT a.id,a.type,a.title,a.details,a.region,a.blood_type,a.status,a.latitude,a.longitude,a.created_at,(SELECT COUNT(*) FROM announcement_photos p WHERE p.announcement_id=a.id) AS photo_count FROM announcements a WHERE ${where.join(' AND ')} ORDER BY a.created_at ${sort},a.id ${sort} LIMIT ${limit} OFFSET ${offset}`,values);
    res.set('Cache-Control','no-store').json({items:rows.map(r=>safeAnnouncement(r)),total:Number(countRows[0]?.total||0),page,limit});
  }catch(e){next(e)}
});
app.get('/api/impact',async(req,res,next)=>{try{await featureTablesReady;const [[notices]]=await pool.execute("SELECT COUNT(*) AS total,SUM(status='resolved') AS resolved FROM announcements WHERE status IN ('verified','resolved') AND title NOT LIKE '[آزمایشی] غیرواقعی:%'");const [[donors]]=await pool.execute("SELECT COUNT(*) AS total FROM blood_donors WHERE status='verified' AND region NOT LIKE 'نمونه آزمایشی · %'");res.json({announcements:Number(notices.total||0),resolved:Number(notices.resolved||0),donors:Number(donors.total||0)})}catch(e){next(e)}});
app.get('/api/donors',async(req,res,next)=>{try{await featureTablesReady;const values=[],where=["status='verified'"];if(['O+','O-','A+','A-','B+','B-','AB+','AB-'].includes(req.query.bloodType)){where.push('blood_type=?');values.push(req.query.bloodType)}if(typeof req.query.region==='string'&&req.query.region.trim()){where.push('region LIKE ?');values.push(`%${req.query.region.trim().slice(0,100)}%`)}const [rows]=await pool.execute(`SELECT id,region,blood_type,created_at FROM blood_donors WHERE ${where.join(' AND ')} ORDER BY created_at DESC LIMIT 100`,values);res.json(rows.map(row=>({id:row.id,region:row.region,bloodType:row.blood_type,createdAt:row.created_at})))}catch(e){next(e)}});
app.post('/api/donors',async(req,res,next)=>{try{await featureTablesReady;const {region,bloodType,contactName,contactPhone,consent}=req.body||{};if(typeof region!=='string'||region.trim().length<2||region.trim().length>100||!['O+','O-','A+','A-','B+','B-','AB+','AB-'].includes(bloodType)||!validPhone(contactPhone)||consent!=='on')return res.status(400).json({error:'INVALID_DONOR_REGISTRATION'});const [result]=await pool.execute('INSERT INTO blood_donors(region,blood_type,contact_name_enc,contact_phone_enc,status) VALUES(?,?,?,?,\'pending\')',[region.trim(),bloodType,encrypt(String(contactName||'').trim().slice(0,120)),encrypt(contactPhone)]);res.status(201).json({id:result.insertId,status:'pending'})}catch(e){next(e)}});
app.post('/api/announcements/:id/feedback',async(req,res,next)=>{try{await featureTablesReady;const id=Number(req.params.id),{kind,reason,details,contactName,contactPhone}=req.body||{};if(!Number.isSafeInteger(id)||id<1||!['tip','report'].includes(kind)||typeof details!=='string'||details.trim().length<8||details.length>2000||contactPhone&&!validPhone(contactPhone))return res.status(400).json({error:'INVALID_FEEDBACK'});if(kind==='report'&&!['false','inappropriate','duplicate','other'].includes(reason))return res.status(400).json({error:'INVALID_REPORT_REASON'});const [exists]=await pool.execute("SELECT id FROM announcements WHERE id=? AND status='verified' LIMIT 1",[id]);if(!exists.length)return res.status(404).json({error:'ANNOUNCEMENT_NOT_FOUND'});await pool.execute('INSERT INTO announcement_feedback(announcement_id,kind,reason,details,contact_name_enc,contact_phone_enc) VALUES(?,?,?,?,?,?)',[id,kind,kind==='report'?reason:null,details.trim(),encrypt(String(contactName||'').trim().slice(0,120)),encrypt(contactPhone||'')]);res.status(201).json({status:'received'})}catch(e){next(e)}});
app.get('/api/my-announcements/:id',async(req,res,next)=>{try{await featureTablesReady;const id=Number(req.params.id),token=String(req.get('x-management-token')||'');if(!Number.isSafeInteger(id)||id<1||token.length<32)return res.status(400).json({error:'INVALID_MANAGEMENT_REQUEST'});const [controls]=await pool.execute('SELECT token_hash FROM announcement_controls WHERE announcement_id=? LIMIT 1',[id]);if(!controls.length||!crypto.timingSafeEqual(Buffer.from(controls[0].token_hash),Buffer.from(sha(token))))return res.status(403).json({error:'INVALID_MANAGEMENT_TOKEN'});const [rows]=await pool.execute('SELECT id,title,details,region,latitude,longitude,status FROM announcements WHERE id=? LIMIT 1',[id]);if(!rows.length)return res.status(404).json({error:'NOT_FOUND'});const row=rows[0];res.set('Cache-Control','no-store').json({id:row.id,title:row.title,details:row.details,region:row.region,latitude:row.latitude,longitude:row.longitude,status:row.status})}catch(e){next(e)}});
app.patch('/api/my-announcements/:id',async(req,res,next)=>{try{await featureTablesReady;const id=Number(req.params.id),{token,title,details,region,latitude,longitude,status}=req.body||{};if(!Number.isSafeInteger(id)||id<1||typeof token!=='string'||token.length<32)return res.status(400).json({error:'INVALID_MANAGEMENT_REQUEST'});const [controls]=await pool.execute('SELECT token_hash FROM announcement_controls WHERE announcement_id=? LIMIT 1',[id]);if(!controls.length||!crypto.timingSafeEqual(Buffer.from(controls[0].token_hash),Buffer.from(sha(token))))return res.status(403).json({error:'INVALID_MANAGEMENT_TOKEN'});if(status==='resolved'){await pool.execute("UPDATE announcements SET status='resolved' WHERE id=?",[id]);return res.json({id,status:'resolved'})}if(typeof title!=='string'||title.trim().length<5||title.length>180||typeof details!=='string'||details.trim().length<10||details.length>4000||typeof region!=='string'||region.trim().length<2||region.trim().length>100||!validCoords(latitude,longitude))return res.status(400).json({error:'INVALID_ANNOUNCEMENT'});await pool.execute("UPDATE announcements SET title=?,details=?,region=?,latitude=?,longitude=?,status='pending' WHERE id=?",[title.trim(),details.trim(),region.trim(),latitude==null?null:Number(latitude),longitude==null?null:Number(longitude),id]);res.json({id,status:'pending'})}catch(e){next(e)}});

app.post('/api/announcements',async(req,res,next)=>{
  try{
    await featureTablesReady;
    const {type,title,details,region,bloodType,contactName,contactPhone,latitude,longitude,photos,photoConsent}=req.body||{};
    if(!['blood','missing','found'].includes(type)||typeof title!=='string'||title.trim().length<5||title.length>180||typeof details!=='string'||details.trim().length<10||details.length>4000||typeof region!=='string'||region.trim().length<2||region.length>100) return res.status(400).json({error:'INVALID_ANNOUNCEMENT'});
    if(type==='blood'&&!['O+','O-','A+','A-','B+','B-','AB+','AB-'].includes(bloodType)) return res.status(400).json({error:'INVALID_BLOOD_TYPE'});
    if(!Array.isArray(photos)||photos.length>2||(type==='blood'&&photos.length>0)) return res.status(400).json({error:'INVALID_PHOTOS'});
    if(photos.length>0&&photoConsent!=='on') return res.status(400).json({error:'PHOTO_CONSENT_REQUIRED'});
    const decodedPhotos=photos.map(decodePhoto);
    if(decodedPhotos.some(photo=>!photo)) return res.status(400).json({error:'INVALID_PHOTOS'});
    if(contactPhone&&!validPhone(contactPhone)) return res.status(400).json({error:'PHONE_MUST_BE_E164'});
    if(!validCoords(latitude,longitude)) return res.status(400).json({error:'INVALID_COORDINATES'});
    const [recent]=await pool.execute("SELECT id FROM announcements WHERE type=? AND region=? AND title=? AND created_at>UTC_TIMESTAMP()-INTERVAL 30 MINUTE LIMIT 1",[type,region.trim(),title.trim()]);
    if(recent.length) return res.status(429).json({error:'DUPLICATE_RECENT_ANNOUNCEMENT'});
    const conn=await pool.getConnection(),managementToken=crypto.randomBytes(32).toString('base64url');
    let result;
    try{
      await conn.beginTransaction();
      const [inserted]=await conn.execute('INSERT INTO announcements(type,title,details,region,blood_type,contact_name_enc,contact_phone_enc,latitude,longitude,status) VALUES(?,?,?,?,?,?,?,?,?,\'pending\')',[type,title.trim(),details.trim(),region.trim(),type==='blood'?bloodType:null,encrypt((contactName||'').trim().slice(0,120)),encrypt(contactPhone||''),latitude==null?null:Number(latitude),longitude==null?null:Number(longitude)]);
      result=inserted;
      await conn.execute('INSERT INTO announcement_controls(announcement_id,token_hash) VALUES(?,?)',[result.insertId,sha(managementToken)]);
      for(let i=0;i<decodedPhotos.length;i++) await conn.execute('INSERT INTO announcement_photos(announcement_id,photo_index,mime_type,photo_data) VALUES(?,?,?,?)',[result.insertId,i+1,decodedPhotos[i].mimeType,decodedPhotos[i].data]);
      await conn.commit();
    }catch(error){await conn.rollback().catch(()=>{});throw error}finally{conn.release()}
    res.set('Cache-Control','no-store').status(201).json({id:result.insertId,status:'pending',managementToken,message:'ANNOUNCEMENT_SUBMITTED'});
  }catch(e){next(e)}
});

app.post('/api/auth/login',async(req,res,next)=>{
  try{
    const phone=String(req.body?.phone||''),code=String(req.body?.code||'');
    if(!validPhone(phone)) return res.status(400).json({error:'INVALID_PHONE'});
    if(!isAdminPhone(phone)) return res.status(403).json({error:'NOT_AN_ADMIN'});
    if(!/^[A-Z2-7]{32,}$/.test(process.env.ADMIN_TOTP_SECRET||'')) return res.status(503).json({error:'TOTP_NOT_CONFIGURED'});
    if(matchingTotpStep(code,process.env.ADMIN_TOTP_SECRET)===null) return res.status(401).json({error:'INVALID_TOTP'});
    const conn=await pool.getConnection();
    const token=crypto.randomBytes(32).toString('base64url');
    try{
      await conn.execute('INSERT INTO admin_sessions(token_hash,phone,expires_at) VALUES(?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 8 HOUR))',[sha(token),phone]);
    }finally{conn.release()}
    res.cookie('admin_session',token,{httpOnly:true,secure:isProd,sameSite:'strict',maxAge:8*60*60*1000,path:'/'}).json({message:'AUTHENTICATED'});
  }catch(e){next(e)}
});
app.post('/api/auth/logout',adminAuth,async(req,res,next)=>{try{const token=req.cookies?.admin_session;if(token)await pool.execute('DELETE FROM admin_sessions WHERE token_hash=?',[sha(token)]);res.clearCookie('admin_session',{httpOnly:true,secure:isProd,sameSite:'strict',path:'/'}).json({message:'LOGGED_OUT'})}catch(e){next(e)}});
app.get('/api/admin/me',adminAuth,(req,res)=>res.json({phone:req.admin.phone}));
app.get('/api/admin/announcements',adminAuth,async(req,res,next)=>{try{await featureTablesReady;const status=['pending','verified','rejected','resolved'].includes(req.query.status)?req.query.status:null;const [rows]=await pool.execute(`SELECT a.*,(SELECT COUNT(*) FROM announcement_photos p WHERE p.announcement_id=a.id) AS photo_count FROM announcements a ${status?'WHERE a.status=?':''} ORDER BY a.created_at DESC LIMIT 300`,status?[status]:[]);res.json(rows.map(r=>safeAnnouncement(r,true)))}catch(e){next(e)}});
app.get('/api/admin/donors',adminAuth,async(req,res,next)=>{try{await featureTablesReady;const status=['pending','verified','rejected'].includes(req.query.status)?req.query.status:null;const [rows]=await pool.execute(`SELECT * FROM blood_donors ${status?'WHERE status=?':''} ORDER BY created_at DESC LIMIT 300`,status?[status]:[]);res.json(rows.map(row=>{const demo=row.region.startsWith('نمونه آزمایشی · ');return {id:row.id,region:row.region,bloodType:row.blood_type,status:row.status,contactName:demo?null:(()=>{try{return decrypt(row.contact_name_enc)}catch{return null}})(),contactPhone:demo?null:(()=>{try{return decrypt(row.contact_phone_enc)}catch{return null}})(),createdAt:row.created_at}}))}catch(e){next(e)}});
app.patch('/api/admin/donors/:id',adminAuth,async(req,res,next)=>{try{await featureTablesReady;const id=Number(req.params.id),{status}=req.body||{};if(!Number.isSafeInteger(id)||id<1||!['verified','rejected'].includes(status))return res.status(400).json({error:'INVALID_DONOR_UPDATE'});const [result]=await pool.execute('UPDATE blood_donors SET status=? WHERE id=?',[status,id]);if(!result.affectedRows)return res.status(404).json({error:'NOT_FOUND'});res.json({id,status})}catch(e){next(e)}});
app.get('/api/admin/feedback',adminAuth,async(req,res,next)=>{try{await featureTablesReady;const status=['pending','reviewed','dismissed'].includes(req.query.status)?req.query.status:null;const [rows]=await pool.execute(`SELECT * FROM announcement_feedback ${status?'WHERE status=?':''} ORDER BY created_at DESC LIMIT 300`,status?[status]:[]);res.json(rows.map(row=>({id:row.id,announcementId:row.announcement_id,kind:row.kind,reason:row.reason,details:row.details,status:row.status,contactName:(()=>{try{return decrypt(row.contact_name_enc)}catch{return null}})(),contactPhone:(()=>{try{return decrypt(row.contact_phone_enc)}catch{return null}})(),createdAt:row.created_at})))}catch(e){next(e)}});
app.patch('/api/admin/feedback/:id',adminAuth,async(req,res,next)=>{try{await featureTablesReady;const id=Number(req.params.id),{status}=req.body||{};if(!Number.isSafeInteger(id)||id<1||!['reviewed','dismissed'].includes(status))return res.status(400).json({error:'INVALID_FEEDBACK_UPDATE'});const [result]=await pool.execute('UPDATE announcement_feedback SET status=? WHERE id=?',[status,id]);if(!result.affectedRows)return res.status(404).json({error:'NOT_FOUND'});res.json({id,status})}catch(e){next(e)}});
app.patch('/api/admin/announcements/:id',adminAuth,async(req,res,next)=>{try{const id=Number(req.params.id),{status}=req.body||{};if(!Number.isSafeInteger(id)||id<1||!['pending','verified','rejected','resolved'].includes(status))return res.status(400).json({error:'INVALID_UPDATE'});const [result]=await pool.execute('UPDATE announcements SET status=? WHERE id=?',[status,id]);if(!result.affectedRows)return res.status(404).json({error:'NOT_FOUND'});res.json({id,status})}catch(e){next(e)}});
app.post('/api/admin/demo-data/approve',adminAuth,async(req,res,next)=>{try{await demoDataReady;const conn=await pool.getConnection();try{await conn.beginTransaction();const [announcements]=await conn.execute("UPDATE announcements SET status='verified' WHERE status='pending' AND title LIKE '[آزمایشی] غیرواقعی:%'");const [donors]=await conn.execute("UPDATE blood_donors SET status='verified' WHERE status='pending' AND region LIKE 'نمونه آزمایشی · %'");await conn.execute("INSERT INTO demo_data_state(state_key,state_value) VALUES('approved_v2','yes') ON DUPLICATE KEY UPDATE state_value='yes'");await conn.commit();res.json({announcements:announcements.affectedRows,donors:donors.affectedRows})}catch(error){await conn.rollback().catch(()=>{});throw error}finally{conn.release()}}catch(e){next(e)}});
app.delete('/api/admin/announcements/:id',adminAuth,async(req,res,next)=>{const conn=await pool.getConnection();try{const id=Number(req.params.id);await conn.beginTransaction();const [result]=await conn.execute('DELETE FROM announcements WHERE id=?',[id]);if(!result.affectedRows){await conn.rollback();return res.status(404).json({error:'NOT_FOUND'})}await conn.execute('DELETE FROM announcement_photos WHERE announcement_id=?',[id]);await conn.commit();res.json({id,deleted:true})}catch(e){await conn.rollback().catch(()=>{});next(e)}finally{conn.release()}});

app.get('/api/photos/:id/:index',async(req,res,next)=>{
  try{await featureTablesReady;const id=Number(req.params.id),index=Number(req.params.index);if(!Number.isSafeInteger(id)||id<1||![1,2].includes(index))return res.status(404).end();const [rows]=await pool.execute("SELECT p.mime_type,p.photo_data FROM announcement_photos p JOIN announcements a ON a.id=p.announcement_id WHERE p.announcement_id=? AND p.photo_index=? AND a.status='verified' LIMIT 1",[id,index]);if(!rows.length)return res.status(404).end();res.set('X-Content-Type-Options','nosniff').set('Cache-Control','public, max-age=3600').type(rows[0].mime_type).send(rows[0].photo_data)}catch(e){next(e)}
});
app.get('/api/admin/photos/:id/:index',adminAuth,async(req,res,next)=>{
  try{await featureTablesReady;const id=Number(req.params.id),index=Number(req.params.index);if(!Number.isSafeInteger(id)||id<1||![1,2].includes(index))return res.status(404).end();const [rows]=await pool.execute('SELECT mime_type,photo_data FROM announcement_photos WHERE announcement_id=? AND photo_index=? LIMIT 1',[id,index]);if(!rows.length)return res.status(404).end();res.set('X-Content-Type-Options','nosniff').set('Cache-Control','private, no-store').type(rows[0].mime_type).send(rows[0].photo_data)}catch(e){next(e)}
});

app.use(express.static(path.join(__dirname,'public')));
for(const asset of ['styles.css','script.js','admin.css','admin.js']) app.get(`/${asset}`,(req,res,next)=>res.sendFile(path.join(__dirname,asset),error=>error&&next(error)));
app.get('/admin',(req,res,next)=>res.sendFile(path.join(__dirname,'admin.html'),error=>error&&next(error)));
app.get('/announcements',(req,res,next)=>res.sendFile(path.join(__dirname,'index.html'),error=>error&&next(error)));
app.get('/',(req,res,next)=>res.sendFile(path.join(__dirname,'index.html'),error=>error&&next(error)));
app.use((err,req,res,next)=>{
  if(res.headersSent)return next(err);
  if(err.code==='PII_ENCRYPTION_KEY_NOT_CONFIGURED'){
    console.error('Announcement submission is unavailable: PII_ENCRYPTION_KEY is missing or invalid.');
    return res.status(503).json({error:'SERVER_CONFIGURATION_ERROR'});
  }
  const databaseErrors=new Set(['ECONNREFUSED','ETIMEDOUT','ENOTFOUND','EHOSTUNREACH','PROTOCOL_CONNECTION_LOST','ER_ACCESS_DENIED_ERROR','ER_BAD_DB_ERROR','ER_NO_SUCH_TABLE']);
  if(databaseErrors.has(err.code)){
    console.error(`Database request failed: ${err.code}`);
    return res.status(503).json({error:'DATABASE_UNAVAILABLE'});
  }
  console.error(err.message);
  res.status(500).json({error:'SERVER_ERROR'});
});
app.listen(port,()=>console.log(`Essential Notices running at http://localhost:${port}`));
