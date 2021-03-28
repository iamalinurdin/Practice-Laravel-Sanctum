<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
  public function register(Request $request)
  {
    $validate = $request->validate([
      'name' => 'required|string|max:255',
      'email' => 'required|string|email|max:255|unique:users',
      'password' => 'required|string|min:8',
    ]);

    $user = User::create([
      'name'     => $validate['name'],
      'email'    => $validate['email'],
      'password' => Hash::make($validate['password']),
    ]);

    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json([
      'access_token' => $token,
      'type_token' => 'Bearer'
    ]);
  }

  public function login(Request $request)
  {
    if (!Auth::attempt($request->only('email', 'password')))
    {
      return response()->json([
        'message' => 'invalid credential'
      ], 401);
    }

    $user  = User::where('email', $request->input('email'))->firstOrFail();
    $token = $user->createToken('auth_token')->plainTextToken;

    return response()->json([
      'access_token' => $token,
      'type_token' => 'Bearer'
    ]);
  }

  public function logout(Request $request)
  {
    $request->user()->tokens()->delete();
    return response()->json([
      'message' => 'logout'
    ], 200);
  }

  public function me(Request $request)
  {
    return $request->user();
  }
}
