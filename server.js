require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const crypto = require('node:crypto');
const path = require('node:path');

const app = express();
const isProd = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3000);
const ttlMinutes = Math.max(2, Number(process.env.OTP_TTL_MINUTES || 5));
const pool = mysql.createPool({host:process.env.DB_HOST,port:Number(process.env.DB_PORT||3306),user:process.env.DB_USER,password:process.env.DB_PASSWORD,database:process.env.DB_NAME,ssl:process.env.DB_SSL==='true'?{minVersion:'TLSv1.2'}:undefined,waitForConnections:true,connectionLimit:10,charset:'utf8mb4',timezone:'Z'});

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false, crossOriginEmbedderPolicy:false}));
app.use(express.json({limit:'9mb'}));
app.use(express.urlencoded({extended:false,limit:'100kb'}));
app.use((req,res,next)=>{const raw=req.headers.cookie||'';req.cookies=Object.fromEntries(raw.split(';').map(part=>part.trim()).filter(Boolean).map(part=>{const i=part.indexOf('=');return [decodeURIComponent(part.slice(0,i)),decodeURIComponent(part.slice(i+1))]}));next()});
app.use('/api/auth', rateLimit({windowMs:15*60*1000,limit:8,standardHeaders:true,legacyHeaders:false}));
app.use('/api/announcements', rateLimit({windowMs:60*60*1000,limit:12,standardHeaders:true,legacyHeaders:false}));

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
  if (!/^[a-f0-9]{64}$/i.test(keyHex)) throw new Error('PII_ENCRYPTION_KEY must be 64 hex characters');
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
function validCoords(lat,lng){return (lat==null&&lng==null)||(Number.isFinite(Number(lat))&&Number.isFinite(Number(lng))&&Math.abs(Number(lat))<=90&&Math.abs(Number(lng))<=180)}

async function sendOtp(phone, code) {
  const {TWILIO_ACCOUNT_SID:sid,TWILIO_AUTH_TOKEN:token,TWILIO_FROM_NUMBER:from}=process.env;
  if(!sid||!token||!from) throw new Error('SMS_PROVIDER_NOT_CONFIGURED');
  const body=new URLSearchParams({To:phone,From:from,Body:`کد ورود پنل اعلانات ضروری: ${code} (اعتبار ${ttlMinutes} دقیقه)`});
  const response=await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`,{method:'POST',headers:{Authorization:`Basic ${Buffer.from(`${sid}:${token}`).toString('base64')}`,'Content-Type':'application/x-www-form-urlencoded'},body});
  if(!response.ok) throw new Error(`SMS_SEND_FAILED_${response.status}`);
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
    const where=["a.status='verified'"], values=[];
    const types=['blood','missing','found'];
    if(types.includes(req.query.type)){where.push('a.type=?');values.push(req.query.type)}
    if(typeof req.query.region==='string'&&req.query.region.length<=100){where.push('a.region LIKE ?');values.push(`%${req.query.region}%`)}
    if(['O+','O-','A+','A-','B+','B-','AB+','AB-'].includes(req.query.bloodType)){where.push('a.blood_type=?');values.push(req.query.bloodType)}
    const [rows]=await pool.execute(`SELECT a.id,a.type,a.title,a.details,a.region,a.blood_type,a.status,a.latitude,a.longitude,a.created_at,(SELECT COUNT(*) FROM announcement_photos p WHERE p.announcement_id=a.id) AS photo_count FROM announcements a WHERE ${where.join(' AND ')} ORDER BY a.created_at DESC LIMIT 100`,values);
    res.json(rows.map(r=>safeAnnouncement(r)));
  }catch(e){next(e)}
});

app.post('/api/announcements',async(req,res,next)=>{
  try{
    const {type,title,details,region,bloodType,contactName,contactPhone,latitude,longitude,photos,photoConsent}=req.body||{};
    if(!['blood','missing','found'].includes(type)||typeof title!=='string'||title.trim().length<5||title.length>180||typeof details!=='string'||details.trim().length<10||details.length>4000||typeof region!=='string'||region.trim().length<2||region.length>100) return res.status(400).json({error:'INVALID_ANNOUNCEMENT'});
    if(type==='blood'&&!['O+','O-','A+','A-','B+','B-','AB+','AB-'].includes(bloodType)) return res.status(400).json({error:'INVALID_BLOOD_TYPE'});
    if(!Array.isArray(photos)||photos.length>2||(type!=='blood'&&photos.length<1)||(type==='blood'&&photos.length>0)) return res.status(400).json({error:type==='blood'?'INVALID_PHOTOS':'PHOTO_REQUIRED'});
    if(type!=='blood'&&photoConsent!=='on') return res.status(400).json({error:'PHOTO_CONSENT_REQUIRED'});
    const decodedPhotos=photos.map(decodePhoto);
    if(decodedPhotos.some(photo=>!photo)) return res.status(400).json({error:'INVALID_PHOTOS'});
    if(contactPhone&&!validPhone(contactPhone)) return res.status(400).json({error:'PHONE_MUST_BE_E164'});
    if(!validCoords(latitude,longitude)) return res.status(400).json({error:'INVALID_COORDINATES'});
    const [recent]=await pool.execute("SELECT id FROM announcements WHERE type=? AND region=? AND title=? AND created_at>UTC_TIMESTAMP()-INTERVAL 30 MINUTE LIMIT 1",[type,region.trim(),title.trim()]);
    if(recent.length) return res.status(429).json({error:'DUPLICATE_RECENT_ANNOUNCEMENT'});
    const conn=await pool.getConnection();
    let result;
    try{
      await conn.beginTransaction();
      const [inserted]=await conn.execute('INSERT INTO announcements(type,title,details,region,blood_type,contact_name_enc,contact_phone_enc,latitude,longitude,status) VALUES(?,?,?,?,?,?,?,?,?,\'pending\')',[type,title.trim(),details.trim(),region.trim(),type==='blood'?bloodType:null,encrypt((contactName||'').trim().slice(0,120)),encrypt(contactPhone||''),latitude==null?null:Number(latitude),longitude==null?null:Number(longitude)]);
      result=inserted;
      for(let i=0;i<decodedPhotos.length;i++) await conn.execute('INSERT INTO announcement_photos(announcement_id,photo_index,mime_type,photo_data) VALUES(?,?,?,?)',[result.insertId,i+1,decodedPhotos[i].mimeType,decodedPhotos[i].data]);
      await conn.commit();
    }catch(error){await conn.rollback().catch(()=>{});throw error}finally{conn.release()}
    res.status(201).json({id:result.insertId,status:'pending',message:'ANNOUNCEMENT_SUBMITTED'});
  }catch(e){next(e)}
});

app.post('/api/auth/request-otp',async(req,res,next)=>{
  try{
    const phone=String(req.body?.phone||'');
    if(!validPhone(phone)) return res.status(400).json({error:'INVALID_PHONE'});
    if(!isAdminPhone(phone)) return res.status(403).json({error:'NOT_AN_ADMIN'});
    const [recent]=await pool.execute('SELECT id FROM admin_otps WHERE phone=? AND created_at>UTC_TIMESTAMP()-INTERVAL 60 SECOND LIMIT 1',[phone]);
    if(recent.length) return res.status(429).json({error:'OTP_COOLDOWN'});
    const code=String(crypto.randomInt(0,1000000)).padStart(6,'0');
    await pool.execute('INSERT INTO admin_otps(phone,otp_hash,expires_at) VALUES(?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL ? MINUTE))',[phone,sha(`${code}:${process.env.SESSION_SECRET}`),ttlMinutes]);
    await sendOtp(phone,code);
    res.json({message:'OTP_SENT'});
  }catch(e){next(e)}
});
app.post('/api/auth/verify-otp',async(req,res,next)=>{
  const conn=await pool.getConnection();
  try{
    const phone=String(req.body?.phone||''),code=String(req.body?.code||'');
    if(!validPhone(phone)||!/^[0-9]{6}$/.test(code)||!isAdminPhone(phone)) return res.status(400).json({error:'INVALID_OTP'});
    await conn.beginTransaction();
    const [rows]=await conn.execute('SELECT id,otp_hash,attempts FROM admin_otps WHERE phone=? AND expires_at>UTC_TIMESTAMP() ORDER BY id DESC LIMIT 1 FOR UPDATE',[phone]);
    if(!rows.length||rows[0].attempts>=5){await conn.rollback();return res.status(401).json({error:'OTP_EXPIRED_OR_INVALID'})}
    if(rows[0].otp_hash!==sha(`${code}:${process.env.SESSION_SECRET}`)){
      await conn.execute('UPDATE admin_otps SET attempts=attempts+1 WHERE id=?',[rows[0].id]);await conn.commit();return res.status(401).json({error:'OTP_EXPIRED_OR_INVALID'});
    }
    await conn.execute('DELETE FROM admin_otps WHERE id=?',[rows[0].id]);
    const token=crypto.randomBytes(32).toString('base64url');
    await conn.execute('INSERT INTO admin_sessions(token_hash,phone,expires_at) VALUES(?,?,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 8 HOUR))',[sha(token),phone]);
    await conn.commit();
    res.cookie('admin_session',token,{httpOnly:true,secure:isProd,sameSite:'strict',maxAge:8*60*60*1000,path:'/'}).json({message:'AUTHENTICATED'});
  }catch(e){await conn.rollback().catch(()=>{});next(e)}finally{conn.release()}
});
app.post('/api/auth/logout',adminAuth,async(req,res,next)=>{try{const token=req.cookies?.admin_session;if(token)await pool.execute('DELETE FROM admin_sessions WHERE token_hash=?',[sha(token)]);res.clearCookie('admin_session',{httpOnly:true,secure:isProd,sameSite:'strict',path:'/'}).json({message:'LOGGED_OUT'})}catch(e){next(e)}});
app.get('/api/admin/me',adminAuth,(req,res)=>res.json({phone:req.admin.phone}));
app.get('/api/admin/announcements',adminAuth,async(req,res,next)=>{try{const status=['pending','verified','rejected','resolved'].includes(req.query.status)?req.query.status:null;const [rows]=await pool.execute(`SELECT a.*,(SELECT COUNT(*) FROM announcement_photos p WHERE p.announcement_id=a.id) AS photo_count FROM announcements a ${status?'WHERE a.status=?':''} ORDER BY a.created_at DESC LIMIT 300`,status?[status]:[]);res.json(rows.map(r=>safeAnnouncement(r,true)))}catch(e){next(e)}});
app.patch('/api/admin/announcements/:id',adminAuth,async(req,res,next)=>{try{const id=Number(req.params.id),{status}=req.body||{};if(!Number.isSafeInteger(id)||id<1||!['pending','verified','rejected','resolved'].includes(status))return res.status(400).json({error:'INVALID_UPDATE'});const [result]=await pool.execute('UPDATE announcements SET status=? WHERE id=?',[status,id]);if(!result.affectedRows)return res.status(404).json({error:'NOT_FOUND'});res.json({id,status})}catch(e){next(e)}});
app.delete('/api/admin/announcements/:id',adminAuth,async(req,res,next)=>{const conn=await pool.getConnection();try{const id=Number(req.params.id);await conn.beginTransaction();const [result]=await conn.execute('DELETE FROM announcements WHERE id=?',[id]);if(!result.affectedRows){await conn.rollback();return res.status(404).json({error:'NOT_FOUND'})}await conn.execute('DELETE FROM announcement_photos WHERE announcement_id=?',[id]);await conn.commit();res.json({id,deleted:true})}catch(e){await conn.rollback().catch(()=>{});next(e)}finally{conn.release()}});

app.get('/api/photos/:id/:index',async(req,res,next)=>{
  try{const id=Number(req.params.id),index=Number(req.params.index);if(!Number.isSafeInteger(id)||id<1||![1,2].includes(index))return res.status(404).end();const [rows]=await pool.execute("SELECT p.mime_type,p.photo_data FROM announcement_photos p JOIN announcements a ON a.id=p.announcement_id WHERE p.announcement_id=? AND p.photo_index=? AND a.status='verified' LIMIT 1",[id,index]);if(!rows.length)return res.status(404).end();res.set('X-Content-Type-Options','nosniff').set('Cache-Control','public, max-age=3600').type(rows[0].mime_type).send(rows[0].photo_data)}catch(e){next(e)}
});
app.get('/api/admin/photos/:id/:index',adminAuth,async(req,res,next)=>{
  try{const id=Number(req.params.id),index=Number(req.params.index);if(!Number.isSafeInteger(id)||id<1||![1,2].includes(index))return res.status(404).end();const [rows]=await pool.execute('SELECT mime_type,photo_data FROM announcement_photos WHERE announcement_id=? AND photo_index=? LIMIT 1',[id,index]);if(!rows.length)return res.status(404).end();res.set('X-Content-Type-Options','nosniff').set('Cache-Control','private, no-store').type(rows[0].mime_type).send(rows[0].photo_data)}catch(e){next(e)}
});

app.use(express.static(path.join(__dirname,'public')));
for(const asset of ['styles.css','script.js','admin.css','admin.js']) app.get(`/${asset}`,(req,res,next)=>res.sendFile(path.join(__dirname,asset),error=>error&&next(error)));
app.get('/admin',(req,res,next)=>res.sendFile(path.join(__dirname,'admin.html'),error=>error&&next(error)));
app.get('/',(req,res,next)=>res.sendFile(path.join(__dirname,'index.html'),error=>error&&next(error)));
app.use((err,req,res,next)=>{console.error(err.message);if(res.headersSent)return next(err);const sms=err.message==='SMS_PROVIDER_NOT_CONFIGURED';res.status(sms?503:500).json({error:sms?'SMS_NOT_CONFIGURED':'SERVER_ERROR'});});
app.listen(port,()=>console.log(`Essential Notices running at http://localhost:${port}`));
