<?php

namespace App\Http\Controllers\API;
  
use App\Http\Controllers\API\BaseController as BaseController;
use App\Models\User;
use Validator;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use App\Mail\OtpMail;

class AuthController extends BaseController
{
 
    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {

        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required',
            'c_password' => 'required|same:password',
            'profile_image' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048', // Optional image field
            'cover_photo' => 'nullable|image|mimes:jpeg,png,jpg,gif|max:2048', // Optional image field
        ]);
     
        if($validator->fails()){
            return $this->sendError('Validation Error.', $validator->errors());       
        }
     
        $input = $request->all();
        $input['password'] = bcrypt($input['password']);

         // Handle profile_image if provided
        if ($request->hasFile('profile_image')) {
            $profileImage = $request->file('profile_image');
            $profileImageName = time() . '_' . uniqid() . '.' . $profileImage->getClientOriginalExtension();
            $profileImage->storeAs('public/profile_images', $profileImageName);
            $input['profile_image'] = 'profile_images/' . $profileImageName;
        }

        // Handle cover_photo if provided
        if ($request->hasFile('cover_photo')) {
            $coverPhoto = $request->file('cover_photo');
            $coverPhotoName = time() . '_' . uniqid() . '.' . $coverPhoto->getClientOriginalExtension();
            $coverPhoto->storeAs('public/cover_photos', $coverPhotoName);
            $input['cover_photo'] = 'cover_photos/' . $coverPhotoName;
        }

            // Generate OTP
        $otp = rand(100000, 999999);
        $input['otp'] = $otp;

        // Create user
        $user = User::create($input);

        // Send OTP to user email
        Mail::to($user->email)->send(new OtpMail($otp));

        $success['user'] =  $user;
    
        return response()->json(['success' => 'User registered successfully. An OTP has been sent to your email.', 'user' => $user], 201);
    }
  
    public function verifyOtp(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email|exists:users,email',
            'otp' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)->where('otp', $request->otp)->first();

        if (!$user) {
            return response()->json(['error' => 'Invalid OTP or email.'], 400);
        }

        // Mark the user as verified
        $user->is_verified = true;
        $user->otp = null; // Clear the OTP after verification
        $user->save();

        return response()->json(['success' => 'Email verified successfully.', 'user' => $user], 200);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    // public function login()
    // {
    //     $credentials = request(['email', 'password']);
  
    //     if (! $token = auth()->attempt($credentials)) {
    //         return $this->sendError('Unauthorised.', ['error'=>'Unauthorised']);
    //     }
  
    //     $success = $this->respondWithToken($token);
    //     return $this->sendResponse($success,'User login successfully.');
    // }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        $user = User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        if (!$user->is_verified) {
            return response()->json(['error' => 'Your email is not verified. Please verify it first.'], 403);
        }

        $token = $user->createToken('MyApp')->accessToken;

        return response()->json(['success' => 'User logged in successfully.', 'token' => $token, 'user' => $user], 200);
    }
  
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function profile()
    {
        $success = auth()->user();
   
        return $this->sendResponse($success, 'Refresh token return successfully.');
    }
  
    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();
        
        return $this->sendResponse([], 'Successfully logged out.');
    }
  
    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        $success = $this->respondWithToken(auth()->refresh());
   
        return $this->sendResponse($success, 'Refresh token return successfully.');
    }
  
    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return [
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ];
    }
}
