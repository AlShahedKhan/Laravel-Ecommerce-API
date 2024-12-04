<?php

use App\Http\Controllers\Api\ApiController;
use Illuminate\Support\Facades\Route;

// Open Routes
Route::post("register", [ApiController::class, "register"]);
Route::post("login", [ApiController::class, "login"]);
Route::post('forgot-password', [ApiController::class, 'forgotPassword']);
Route::post('reset-password', [ApiController::class, 'resetPassword']);


// Protected Routes
Route::group([
    "middleware" => ["auth:api"]
], function () {
    Route::get("profile", [ApiController::class, "profile"]);
    Route::get("refresh-token", [ApiController::class, "refreshToken"]);
    Route::get("logout", [ApiController::class, "logout"]);
});
