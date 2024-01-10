import Foundation
import Capacitor
import FirebaseCore
import FirebaseAuth

class PhoneAuthProviderHandler: NSObject {
    private var pluginImplementation: FirebaseAuthentication
    private var signInOnConfirm = true
    private var skipNativeAuthOnConfirm = false

    init(_ pluginImplementation: FirebaseAuthentication) {
        self.pluginImplementation = pluginImplementation
        super.init()
    }

    func signIn(call: CAPPluginCall) {
        let phoneNumber = call.getString("phoneNumber");
        
        if phoneNumber == nil {
            let email = call.getString("email")!;
            let password = call.getString("password")!;
            
            Auth.auth().signIn(withEmail: email,
                               password: password) { (result, error) in
              let authError = error as NSError?
              if (authError == nil || authError!.code != AuthErrorCode.secondFactorRequired.rawValue) {
                // User is not enrolled with a second factor and is successfully signed in.
                // ...
              } else {
                let resolver = authError!.userInfo[AuthErrorUserInfoMultiFactorResolverKey] as! MultiFactorResolver
                // Ask user which second factor to use.
                let hint = resolver.hints[0] as! PhoneMultiFactorInfo
                // Send SMS verification code
                PhoneAuthProvider.provider().verifyPhoneNumber(
                  with: hint,
                  uiDelegate: nil,
                  multiFactorSession: resolver.session) { (verificationId, error) in
                      if let error = error {
                          self.pluginImplementation.handleFailedSignIn(message: nil, error: error)
                          return
                      }
                      
                      var result = FirebaseAuthenticationHelper.createSignInResult(credential: nil, user: nil, idToken: nil, nonce: nil, accessToken: nil, serverAuthCode: nil, additionalUserInfo: nil, displayName: nil, authorizationCode: nil)
                      result["verificationId"] = verificationId
                      call.resolve(result)
                }
              }
            }
            
        } else {
            
            guard let phoneNumber = phoneNumber else {
                return
            }
            PhoneAuthProvider.provider()
                .verifyPhoneNumber(phoneNumber, uiDelegate: nil) { verificationID, error in
                    if let error = error {
                        self.pluginImplementation.handleFailedSignIn(message: nil, error: error)
                        return
                    }

                    var result = FirebaseAuthenticationHelper.createSignInResult(credential: nil, user: nil, idToken: nil, nonce: nil, accessToken: nil, serverAuthCode: nil, additionalUserInfo: nil, displayName: nil, authorizationCode: nil)
                    result["verificationId"] = verificationID
                    call.resolve(result)
                }
            
        }
        
    
    }

    func link(_ options: LinkWithPhoneNumberOptions) {
        signInOnConfirm = false
        skipNativeAuthOnConfirm = options.getSkipNativeAuth()
        verifyPhoneNumber(options)
    }

    func confirmVerificationCode(_ options: ConfirmVerificationCodeOptions, completion: @escaping (Result?, Error?) -> Void) {
        let credential = PhoneAuthProvider.provider().credential(
            withVerificationID: options.getVerificationId(),
            verificationCode: options.getVerificationCode()
        )
        if self.signInOnConfirm {
            pluginImplementation.signInWithCredential(SignInOptions(skipNativeAuth: skipNativeAuthOnConfirm), credential: credential, completion: completion)
        } else {
            pluginImplementation.linkWithCredential(credential: credential, completion: completion)
        }
    }

    private func verifyPhoneNumber(_ options: SignInWithPhoneNumberOptions) {
        PhoneAuthProvider.provider()
            .verifyPhoneNumber(options.getPhoneNumber(), uiDelegate: nil) { verificationID, _ in
                self.pluginImplementation.handlePhoneCodeSent(verificationID ?? "")
            }
    }
}
