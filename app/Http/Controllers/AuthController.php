<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validated = $request->validate([
            'username' => 'required|string|unique:users',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:6',
            'phone_number' => 'nullable|string',
            'address' => 'nullable|string',
            'profile_picture' => 'nullable|string',
            'device' => 'nullable|string',
            'role' => 'in:user,admin',
            'status' => 'in:active,inactive,banned,premium',
        ]);
    
        $user = User::create([
            'username' => $validated['username'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
            'phone_number' => $validated['phone_number'] ?? null,
            'address' => $validated['address'] ?? null,
            'profile_picture' => $validated['profile_picture'] ?? null,
            'device' => $validated['device'] ?? null,
            'role' => $validated['role'] ?? 'user',
            'status' => $validated['status'] ?? 'active',
            'last_login' => now(),
        ]);
    
        $token = $user->createToken('auth_token')->plainTextToken;
    
        return response()->json([
            'message' => 'User registered successfully!',
            'user' => $user,
            'token' => $token,
        ]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);
    
        $user = User::where('email', $request->email)->first();
    
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Invalid credentials'
            ], 401);
        }
    
        // Update last_login
        $user->last_login = now();
        $user->save();
    
        $token = $user->createToken('auth_token')->plainTextToken;
    
        return response()->json([
            'message' => 'Login successful',
            'user' => $user,
            'token' => $token,
        ]);
    }

    public function update(Request $request)
    {
        $user = $request->user();

        $validated = $request->validate([
            'username' => 'sometimes|string|max:255|unique:users,username,' . $user->id,
            'email' => 'sometimes|email|unique:users,email,' . $user->id,
            'password' => 'sometimes|string|min:6|confirmed',
            'phone_number' => 'sometimes|string',
            'address' => 'sometimes|string',
            'profile_picture' => 'sometimes|url',
            'device' => 'sometimes|string',
            'status' => 'sometimes|in:active,inactive,banned,premium',
        ]);

        if (isset($validated['password'])) {
            $validated['password'] = bcrypt($validated['password']);
        }

        $user->update($validated);

        return response()->json([
            'message' => 'User updated successfully',
            'user' => $user
        ]);
    }


    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logged out successfully'
        ]);
    }

}
