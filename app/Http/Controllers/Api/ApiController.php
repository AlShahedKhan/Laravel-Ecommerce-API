<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use App\Traits\AuthTrait;
use App\Traits\HandlesApiResponse;
use Illuminate\Support\Facades\Hash;

class ApiController extends Controller
{
    use HandlesApiResponse;
    use AuthTrait;
    // Register API [POST] (name, email, password, phone_no)
    public function register(RegisterRequest $request)
    {
        return $this->safeCall(function () use ($request) {
            // User
            $user = User::create([
                "name" => $request->name,
                "email" => $request->email,
                "password" => bcrypt($request->password),
            ]);

            $token = $user->createToken('myToken')->accessToken;

            $cookie = cookie('access_token', $token, 60 * 24);

            return $this->successResponse(
                'User registered successfully',
                ['token' => $token],
            )->cookie($cookie);
        });
    }

    // Login API (POST) [email, password]
    public function login(LoginRequest $request)
    {
        return $this->safeCall(function () use ($request) {
            // Check user by "email" value
            $user = User::where("email", $request->email)->first();

            if (!$user || !Hash::check($request->password, $user->password)) {
                return $this->errorResponse(
                    'Invalid credentials',
                    401
                );
            }

            // Generate auth token
            $token = $user->createToken('myToken')->accessToken;

            return $this->successResponse(
                'User logged in successfully',
                ['token' => $token],
            );
        });
    }

    // Profile API (GET) (Auth Token - Header)


    // Logout API (GET) (Auth Token - Header)
    public function logout()
    {
        return $this->safeCall(function () {
            request()->user()->tokens()->delete();

            return $this->successResponse(
                'User logged out successfully'
            );
        });
    }


}
