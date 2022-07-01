<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Tymon\JWTAuth\JWTAuth;
use App\Models\User;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Validation\Validator as ValidationValidator;
use Illuminate\Support\Facades\Validator as FacadesValidator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Validator;

class ApiController extends Controller
{
    public function register(Request $request){
        $data= $request->only('name','email','password');
        $validator = Validator::make($data, [
            'name'      => 'required|string',
            'email'      => 'required|email|unique:users',
            'password'      => 'required|string|min:6|max:50',
        ]);

        if($validator->fails()) {
            return response()->json(['error'=> $validator->messages()], 200);
        }

        // apabila valid
        //

        $user = User::create([
            'name'      => $request->name,
            'email'      => $request->email,
            'password'      => bcrypt ($request->password)
        ]);

        return response()->json([
            'success'   => true,
            'messages'   => 'ser created succesfully',
            'success'   => $user
        ], Response::HTTP_OK);
    }

    public function authenticate(Request $request)
    {
        $credentials = $request->onkly('email','password');
        $validator = Validator::make($credentials,[
            'email' => 'required|email',
            'password' => 'required|string|min:6|max:50'
        ]);

        if($validator->fails()) {
            return response()->json(['error'=>$validator->messages], 200);
        }
        
        try {
            if(! $token = JWTAuth::attempt($$credentials)){
                return response()->json([
                    'success'   => false,
                    'messages'  => 'Login credentials are invalid'
                ], 400);
            }
        }   catch (JWTException $e) {
            return $credentials;
            return response()->json([
                'success'   => false,
                'messages'   => 'Cloud not create token'
            ], 500);
        }
        return response()->json([
            'success'   => true,
            'token'     => $token
        ], 200);
    }

    public function logout(Request $request)
    {
        //valid credential
        $validator = Validator::make($request->only('token'),[
            'token' => 'required'
        ]);

        //send failed response if request is not valid
        if ($validator->fails()) {
            return response()->json(['error' =>$validator->messages()], 200);
        }

        //request is validated, do logout
        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success'   => false,
                'messages'   => 'User has been logged out'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success'   => false,
                'messages'   => 'Sorry, user cannot be logged out'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function get_user($request)
    {
        $this->validate($request, [
            'token' => 'requied'
        ]);

        $user = JWTAuth::authenticate($request->token);

        return response()->json(['user' => $user]);
    }
}