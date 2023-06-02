<?php

namespace App\Http\Controllers\Api\Auth;

class OAuthController extends Controller
{
    public function login(Request $request): ?Response
    {
        $isvalid = $this->validateRequest($request);
        if ($isvalid !== true) {
            return $isvalid;
        }

        $email = $request->input('email');
        $password = $request->input('password');

        if (Auth::attempt(['email' => $email, 'password' => $password])) {
            $request->session()->put('oauth', true);
            $request->session()->put('email', $email);
            $request->session()->put('password', $this->encrypter->encrypt($password));

            $this->fixRequest($request);

            Redirect::setIntendedUrl(route('oauth.verify'));

            return Route::respondWithRoute('oauth.verify');
        }

        return $this->respondUnauthorized();
    }
    //
    public function verify(Request $request): JsonResponse
    {
        $response = $this->handleVerify($request);

        Auth::logout();
        $request->session()->flush();

        return $response ?: $this->respondUnauthorized();
    }

    private function handleVerify(Request $request): ?JsonResponse
    {
        if (! $request->session()->has('email') || ! $request->session()->has('password')) {
            return null;
        }

        $request->query->set('email', $request->session()->pull('email'));
        $request->query->set('password', $this->encrypter->decrypt($request->session()->pull('password')));

        $isvalid = $this->validateRequest($request);
        if ($isvalid !== true) {
            return $isvalid;
        }

        try {
            $token = $this->proxy([
                'username' => $request->input('email'),
                'password' => $request->input('password'),
                'grantType' => 'password',
            ]);

            return $this->respond($token);
        } catch (\Exception $e) {
            return null;
        }
    }

    private function proxy(array $data = []): array
    {
        $url = App::runningUnitTests() ? Str::of(config('app.url'))->ltrim('/').'/oauth/token' : route('passport.token');
        /** @var \Illuminate\Http\Response */
        $response = app(Kernel::class)->handle(Request::create($url, 'POST', [
            'grant_type' => $data['grantType'],
            'client_id' => config('passport.password_grant_client.id'),
            'client_secret' => config('passport.password_grant_client.secret'),
            'username' => $data['username'],
            'password' => $data['password'],
            'scope' => '',
        ]));

        $data = json_decode($response->content());

        return [
            'access_token' => $data->access_token,
            'expires_in' => $data->expires_in,
        ];
    }
}
