<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{

    public function register(Request $request) {


        Log::info(print_r($request->all(),true));

        // validate the request
        $data  = $request->validate([
            'name' => 'string|required',
            'email' => 'required|string|email|unique:users,email',
            'password' => 'required|min:8|max:255'
        ]);

        // Create a user model
        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => bcrypt($data['password'])
        ]);

        // Send Email Varification
        //$user->sendEmailVerificationNotification();

        // Generate token for user
        $token = $user->createToken('main')->plainTextToken;

        return response([
            'user' => $user,
            'token' => $token
        ]);
    }

    public function login(Request $request) {

        $credentials = $request->validate([

            'email' => 'required|email|string|exists:users,email',
            'password' => [
                'required',
            ],
            'remember' => 'boolean'
        ]);

        $remember = $credentials['remember'] ?? false;
        unset($credentials['remember']);


        if (!Auth::attempt($credentials,$remember)) {
            return response([
                'error' => 'The Provided Credentials are incorrect'
            ], 422);
        }

        $user = Auth::user();

        $token = $user->createToken('main')->plainTextToken;

        return response([
            'user' => $user,
            'token' => $token
        ]);
    }

    public function logout(){
        $user = Auth::user();

        $user->currentAccessToken()->delete();

        return response([
            'success' => true
        ]);
    }

//    public function getAuthenticatedUser(Request $request) {
//        return $request->user();
//    }
//
//
//    public function sendPasswordResetLinkEmail(Request $request) {
//        $request->validate(['email' => 'required|email']);
//
//        $status = Password::sendResetLink(
//            $request->only('email')
//        );
//
//        if($status === Password::RESET_LINK_SENT) {
//            return response(['message' => __($status)] , 200);
//        } else {
//            throw ValidationException::withMessages([
//                'email' => __($status)
//            ]);
//        }
//    }
//
//    public function resetPassword(Request $request) {
//        $request->validate([
//            'token' => 'required',
//            'email' => 'required|email',
//            'password' => 'required|min:8',
//        ]);
//
//        $status = Password::reset(
//            $request->only('email', 'password', 'token'),
//            function ($user, $password) use ($request) {
//                $user->forceFill([
//                    'password' => Hash::make($password)
//                ])->setRememberToken(Str::random(60));
//
//                $user->save();
//
//                event(new PasswordReset($user));
//            }
//        );
//
//        if($status == Password::PASSWORD_RESET) {
//            return response()->json(['message' => __($status)], 200);
//        } else {
//            throw ValidationException::withMessages([
//                'email' => __($status)
//            ]);
//        }
//    }
//
//    public function verify($user_id, Request $request) {
//        if (!$request->hasValidSignature()) {
//            return response()->json(["msg" => "Invalid/Expired url provided."], 401);
//        }
//
//        $user = User::findOrFail($user_id);
//
//        if (!$user->hasVerifiedEmail()) {
//            $user->markEmailAsVerified();
//        }
//
//        $token = $user->createToken('main')->plainTextToken;
//        return redirect()->to(getenv('APP_URL').'/verified'); //todo change the link to be dynamic in the env
//    }
//
//    public function resend(Request $request) {
//
//        $user = $request->user();
//        if ($user->hasVerifiedEmail()) {
//            return response()->json(["message" => "Email already verified."], 400);
//        }
//
//        $user->sendEmailVerificationNotification();
//
//        return response()->json(["message" => "Email verification link sent on your email id"]);
//    }
}
