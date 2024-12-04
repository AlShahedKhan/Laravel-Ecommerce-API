<?php

namespace App\Traits;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use App\Http\Requests\ResetPasswordRequest;
use App\Http\Requests\ForgotPasswordRequest;

trait AuthTrait
{
    use HandlesApiResponse;
    public function profile()
    {
        return $this->safeCall(function () {
            $user = Auth::user();

            return $this->successResponse(
                'User profile data',
                ['user' => $user],
            );
        });
    }

    // Refresh Token API (GET) (Auth Token - Header)
    public function refreshToken()
    {
        return $this->safeCall(function () {
            $user = request()->user(); //user data
            $token = $user->createToken("newToken");

            $refreshToken = $token->accessToken;

            return $this->successResponse(
                'Token refreshed successfully',
                ['token' => $refreshToken],
            );
        });
    }
    public function forgotPassword(ForgotPasswordRequest $request)
    {
        return $this->safeCall(function () use ($request) {

            // Generate a password reset token
            $status = Password::sendResetLink($request->only('email'));

            if ($status === Password::RESET_LINK_SENT) {
                return $this->successResponse(
                    'Password reset link sent to your email.'
                );
            }
            return $this->errorResponse('Failed to send password reset link.', 500);
        });
    }



    // Reset Password API (POST)
    public function resetPassword(ResetPasswordRequest $request)
    {
        return $this->safeCall(function () use ($request) {

            // Reset the password
            $status = Password::reset(
                $request->only('email', 'password', 'password_confirmation', 'token'),
                function ($user, $password) {
                    $user->forceFill([
                        'password' => Hash::make($password),
                    ])->save();
                }
            );

            if ($status === Password::PASSWORD_RESET) {
                return $this->successResponse('Password reset successfully.');
            }

            return $this->errorResponse('Failed to reset password.', 500);
        });
    }
}
