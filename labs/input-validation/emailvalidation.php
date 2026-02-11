<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class EmailValidationController extends Controller
{
  
    public function verValid(Request $request)
    {
        try {
            
            $emailf = $request->input('email', '');
            $passf  = $request->input('password', '');

            $email = strtolower(trim((string) $emailf));
            $password = trim((string) $passf);

            //cek validasi email
            $emailCheck = $this->Check_val('email', $email);
            if ($emailCheck !== true) {
                return response()->json([
                    'ok' => false,
                    'field' => 'email',
                    'message' => $emailCheck,
                ], 422);
            }

            //cek validasi untuk password
            $passCheck = $this->Check_val('password', $password);
            if ($passCheck !== true) {
                return response()->json([
                    'ok' => false,
                    'field' => 'password',
                    'message' => $passCheck,
                ], 422);
            }

            // kalau sukses lanjutkan proses aja  
            return response()->json([
                'ok' => true,
                'message' => 'Valid',
                'data' => [
                    'email' => $email, 
                ]
            ], 200);

        } catch (\Throwable $e) {
            // data error tangkap di sini dulu
            return response()->json([
                'ok' => false,
                'message' => 'ada kesalahan silahkan coba lagi'
            ], 422);
        }
    }

    //chek Validasi ada di sini 
    private function Check_val(string $type, string $value)
    {
        if ($type === 'email') {
            // jika datanya kosong
            if ($value === '') {
                return 'Email tidak boleh kosong. Contoh email: user@gmail.com';
            }

            // max email di kasih 30 dulu aja
            if (mb_strlen($value) > 30) {
                return 'Email terlalu panjang (maks 30 karakter). Contoh email: user@gmail.com';
            }

            // harus ada @
            if (strpos($value, '@') === false) {
                return 'Format anda salah, contoh email user@gmail.com';
            }

            // format email valid cek validasi email
            if (!filter_var($value, FILTER_VALIDATE_EMAIL)) {
                return 'Format anda salah, contoh email user@gmail.com';
            }

            // domain whitelus nya
            $domain = $this->getEmailDom($value);
            if ($domain === '') {
                return 'Format anda salah, contoh email user@gmail.com';
            }

            $alwdom = ['gmail.com', 'yahoo.com']; //domain yang di perboloehkan, sekarang hardcode nanti kita masukin DB biar dinamic


            if (!in_array($domain, $alwdom, true)) {
                return 'Domain tidak diizinkan. Gunakan gmail.com atau yahoo.com';
            }

            return true;
        }

        if ($type === 'password') {
            if ($value === '') {
                return 'Password tidak boleh kosong.';
            }

            //minimal harus 8 karakter
            if (mb_strlen($value) < 8) {
                return 'Password minimal 8 karakter.';
            }

            // wajib ada uppercase
            if (!preg_match('/[A-Z]/', $value)) {
                return 'Password harus mengandung minimal 1 huruf besar (A-Z).';
            }

            // wajib ada lowercase
            if (!preg_match('/[a-z]/', $value)) {
                return 'Password harus mengandung minimal 1 huruf kecil (a-z).';
            }

            // daftar special yang diizinkan
            $asc = $this->allowedSC();

            // karakter yang g boleh
            if (preg_match('/[*{}()!?"\']/', $value)) {
                return 'Password tidak boleh mengandung karakter: * { } ( ) ! ? " \'';
            }

            // wajib ada di white listnya has Sepecial Char
            $hassc = preg_match(
                '/[' . preg_quote($asc, '/') . ']/',
                $value
            ) === 1;

            if (!$hassc) {
                return 'Password harus mengandung minimal 1 karakter spesial yang diizinkan!!';
            }

            // cuma boleh huruf angka sama yang di white list aja dari polanya atau pattern
            $patall =
                '/\A[a-zA-Z0-9' . preg_quote($asc, '/') . ']+\z/';

            if (!preg_match($patall, $value)) {
                return 'Password mengandung karakter yang tidak diizinkan!!';
            }

            return true;

        }

        return 'Tipe validasi tidak dikenali.';
    }

    //pisahkan domain nya biar ntar kita return domain only 
    private function getEmailDom(string $email): string
    {
        $parts = explode('@', $email);
        if (count($parts) !== 2) return '';
        return strtolower(trim($parts[1]));
    }

    //yang di perbolehkan SC 
    private function allowedSC(): string
    {
        // karakter spesial yang DIIZINKAN
        // tidak termasuk: * { } ! ? " ' ( )
        return '@#$%^&_+-=[]:;<>,./\\|~';
    }
}
