<div dir="rtl" style="font-family: Tahoma;font-size: large">

# ReadMe 
این فایل صرفا جهت معرفی sample code ها می باشد

# JCA/JCE
## ایجاد Provider
قبل از انجام هر کار، لازم است Provider مورد نظر را به برنامه معرفی کنیم. بدین منظور از تابع  getProvider استفاده
میشود. این تابع، نام Provider را گرفته و یک شیئ از نوع آن برمیگرداند

## لاگین کردن به HSM
#### loginAndLoadKeyStore
میتوانیم با استفاده از Provider و PIN(Password) به  HSM لاگین کرد.

## تولید کلید متقارن
#### generateSymmetricAES128
برای تولید کلید متقارن کافیست Provider را به شیئای از نوع KeyGenerator معرفی نموده و پارامترهای کلید را برای آن
تعیین کنید. این پارامترها شامل نوع کلید و در صورت نیاز طول آن میشوند.

## ذخیره کلید متقارن در HSM
#### saveSymmetricKeyInHSM
برای ذخیره کلید در HSM ابتدا یک شیئ از نوع SecretKeyEntry ایجاد کرده و SecretKey مربوط به کلید تولید شده بهمراه یک نام در HSM ذخیره میگردد.

## رمز کردن یک متن با کلید متقارن
#### encryptByAES
برای رمز کردن یک متن ساده لازم است یک شیئ از نوع Cipher ایجاد کرده و مکانیزم رمزنگاری، کلید رمزنگاری و
Provider را به آن معرفی نمایید.

## رمز گشایی متن رمز شده با کلید متقارن
#### decryptByAES
عمل رمزگشایی دقیقا مشابه با رمزنگاری انجام میشود، با این تفاوت که الگ.ریتم Cipher میبایست از نوع DECRYPT_MODE باشد.

## تولید چکیده پیام
#### messageDigestSHA256
جهت استفاده از توابع چکیده سازی لازم است یک شیئ از نوع MessageDigest ایجاد نموده و الگوریتم چکیده سازی و
Provider را برای آن مشخص کنید.

## تولید زوج کلید نامتقارن
#### generateKeyPair
برای تولید کلید نامتقارن لازم است یک شیئ از نوع KeyPairGenerator ایجاد کرده و نوع کلید RSA و Provider مورد
استفاده را برای آن تعیین نمایید.

## ذخیره certificate
#### generateCertificateAndSave
بوسیله زوج کلید یک certificate self sign ساخته میشود و در HSM ذخیره می گردد

## امضای پیام
#### signData
برای تولید امضا، ابتدا یک شیئ از نوع Signature ایجاد نمایید. در تابع سازنده این شیئ الگوریتم تولید امضا و نیز
Provider مورد استفاده را مشخص کنید.

## ارزیابی امضا
#### verifySign
برای ارزیابی امضا، ابتدا یک شیئ از نوع Signature ایجاد نمایید. در تابع سازندهی این شیئ الگوریتم امضا و نیز Provider
مورد استفاده را مشخص کنید. سپس تابع initVerify را فراخوانی کرده و کلید عمومی مورد استفاده را برای آن تعیین
نمایید.

</div>
