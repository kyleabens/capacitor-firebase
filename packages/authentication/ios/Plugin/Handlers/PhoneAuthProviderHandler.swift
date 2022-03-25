import Foundation
import Capacitor
import FirebaseCore
import FirebaseAuth

class PhoneAuthProviderHandler: NSObject {
    var pluginImplementation: FirebaseAuthentication

    init(_ pluginImplementation: FirebaseAuthentication) {
        self.pluginImplementation = pluginImplementation
        super.init()
    }

    func signIn(call: CAPPluginCall) {
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
                if error != nil {
                  // Failed to verify phone number.
                }
                  var result = FirebaseAuthenticationHelper.createSignInResult(credential: nil, user: nil, idToken: nil, nonce: nil)
                  result["verificationId"] = verificationId
                  call.resolve(result)
            }
          }
        }
    
    }

    private func verifyPhoneNumber(_ call: CAPPluginCall, _ phoneNumber: String?) {
        guard let phoneNumber = phoneNumber else {
            return
        }
        PhoneAuthProvider.provider()
            .verifyPhoneNumber(phoneNumber, uiDelegate: nil) { verificationID, error in
                if let error = error {
                    self.pluginImplementation.handleFailedSignIn(message: nil, error: error)
                    return
                }

                var result = FirebaseAuthenticationHelper.createSignInResult(credential: nil, user: nil, idToken: nil, nonce: nil)
                result["verificationId"] = verificationID
                call.resolve(result)
            }
    }

    private func handleVerificationCode(_ call: CAPPluginCall, _ verificationID: String?, _ verificationCode: String?) {
        guard let verificationID = verificationID, let verificationCode = verificationCode else {
            return
        }
        let credential = PhoneAuthProvider.provider().credential(
            withVerificationID: verificationID,
            verificationCode: verificationCode
        )
        self.pluginImplementation.handleSuccessfulSignIn(credential: credential, idToken: nil, nonce: nil)
    }
}
