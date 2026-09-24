# اعلانات ضروری

اپلیکیشن وب چندزبانه با Express و MySQL. اعلان‌های عمومی فقط پس از تأیید مدیر نمایش داده می‌شوند؛ نام و شماره تماس با AES-256-GCM رمزگذاری شده و فقط در پنل مدیریت رمزگشایی می‌شود.

## پیش‌نیازها

- Node.js 20 یا بالاتر
- MySQL 8 یا MariaDB سازگار
- حساب پیامک Twilio برای OTP پنل مدیر
- کلید Google Maps JavaScript API برای نقشه (اختیاری تا زمان راه‌اندازی)

## راه‌اندازی محلی

1. پایگاه داده را ایجاد کنید: `mysql -u root -p < schema.sql`
2. فایل `.env.example` را به `.env` کپی و تنظیمات دیتابیس را وارد کنید.
3. برای کلیدهای امن:

   ```sh
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```

   مقدار نخست برای `PII_ENCRYPTION_KEY` و مقدار دوم برای `SESSION_SECRET` است.
4. `npm install` سپس `npm start` را اجرا کنید.
5. سایت: `http://localhost:3000` و پنل: `http://localhost:3000/admin`

برای پیامک، `ADMIN_PHONE` را با قالب E.164 تنظیم کنید؛ چند مدیر را با ویرگول جدا کنید. همچنین `TWILIO_ACCOUNT_SID`، `TWILIO_AUTH_TOKEN` و `TWILIO_FROM_NUMBER` را وارد کنید. در حساب آزمایشی Twilio، شماره مقصد باید در حساب تأیید شده باشد. برای Maps، `GOOGLE_MAPS_API_KEY` را تنظیم و کلید مرورگر را به دامنه‌های سایت و Maps JavaScript API محدود کنید. این کلید ذاتاً در مرورگر استفاده می‌شود؛ آن را در سمت سرور به‌عنوان راز نگه ندارید.

## API

- `GET /api/announcements`: فقط اعلان‌های تأییدشده
- `POST /api/announcements`: ثبت اعلان با وضعیت pending
- `POST /api/auth/request-otp`, `POST /api/auth/verify-otp`: ورود مدیر
- `GET /api/admin/announcements`: اعلان‌ها و اطلاعات تماس رمزگشایی‌شده، مدیر-مجاز
- `PATCH /api/admin/announcements/:id`: تغییر وضعیت
- `DELETE /api/admin/announcements/:id`: حذف اعلان

## پیش از انتشار عمومی

از TLS استفاده کنید، کلیدهای API را محدود کنید، برای MySQL کاربر جدا با کمترین دسترسی بسازید، پشتیبان رمزگذاری‌شده بگیرید و دسترسی مدیر را از شماره‌های مورد اعتماد محدود کنید. Twilio برای ارسال پیامک مستندات و محدودیت‌های منطقه‌ای/حساب دارد. نرخ‌محدودسازی پیش‌فرض Express در حافظه است؛ برای چند نمونهٔ سرور، آن را به Redis منتقل کنید. مسیر تماس کاربران، گزارش تخلف، احراز هویت کاربران عادی و گردش‌کار تأیید هویت محلی نیازمند سیاست عملیاتی شما هستند.
