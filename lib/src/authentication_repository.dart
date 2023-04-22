import 'dart:async';

import 'package:authentication_repository/authentication_repository.dart';
import 'package:cache/cache.dart';
import 'package:firebase_auth/firebase_auth.dart' as firebase_auth;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:google_sign_in/google_sign_in.dart';
import 'package:meta/meta.dart';

/// {@template sign_up_with_email_and_password_failure}
/// Thrown if during the sign up process if a failure occurs.
/// {@endtemplate}
class SignUpWithEmailAndPasswordFailure implements Exception {
  /// {@macro sign_up_with_email_and_password_failure}
  const SignUpWithEmailAndPasswordFailure([
    this.message = 'An unknown exception occurred.',
    this.code = '',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  /// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/FirebaseAuth/createUserWithEmailAndPassword.html
  factory SignUpWithEmailAndPasswordFailure.fromCode(String code) {
    switch (code) {
      case 'invalid-email':
        return SignUpWithEmailAndPasswordFailure(
          'Email is not valid or badly formatted.',
          code,
        );
      case 'user-disabled':
        return SignUpWithEmailAndPasswordFailure(
          'This user has been disabled. Please contact support for help.',
          code,
        );
      case 'email-already-in-use':
        return SignUpWithEmailAndPasswordFailure(
          'An account already exists for that email.',
          code,
        );
      case 'operation-not-allowed':
        return SignUpWithEmailAndPasswordFailure(
          'Operation is not allowed.  Please contact support.',
          code,
        );
      case 'weak-password':
        return SignUpWithEmailAndPasswordFailure(
          'Please enter a stronger password.',
          code,
        );
      default:
        return const SignUpWithEmailAndPasswordFailure();
    }
  }

  /// The associated error message.
  final String message;
  final String code;
}

/// {@template log_in_with_email_and_password_failure}
/// Thrown during the login process if a failure occurs.
/// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/FirebaseAuth/signInWithEmailAndPassword.html
/// {@endtemplate}
class LogInWithEmailAndPasswordFailure implements Exception {
  /// {@macro log_in_with_email_and_password_failure}
  const LogInWithEmailAndPasswordFailure([
    this.message = 'An unknown exception occurred.',
    this.code = '',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  factory LogInWithEmailAndPasswordFailure.fromCode(String code) {
    switch (code) {
      case 'invalid-email':
        return LogInWithEmailAndPasswordFailure(
          'Email is not valid or badly formatted.',
          code,
        );
      case 'user-disabled':
        return LogInWithEmailAndPasswordFailure(
          'This user has been disabled. Please contact support for help.',
          code,
        );
      case 'user-not-found':
        return LogInWithEmailAndPasswordFailure(
          'Email is not found, please create an account.',
          code,
        );
      case 'wrong-password':
        return LogInWithEmailAndPasswordFailure(
          'Incorrect password, please try again.',
          code,
        );
      default:
        return const LogInWithEmailAndPasswordFailure();
    }
  }

  /// The associated error message.
  final String message;
  final String code;
}

/// {@template log_in_with_google_failure}
/// Thrown during the sign in with google process if a failure occurs.
/// https://pub.dev/documentation/firebase_auth/latest/firebase_auth/FirebaseAuth/signInWithCredential.html
/// {@endtemplate}
class LogInWithGoogleFailure implements Exception {
  /// {@macro log_in_with_google_failure}
  const LogInWithGoogleFailure([
    this.message = 'An unknown exception occurred.',
    this.code = '',
  ]);

  /// Create an authentication message
  /// from a firebase authentication exception code.
  factory LogInWithGoogleFailure.fromCode(String code) {
    switch (code) {
      case 'account-exists-with-different-credential':
        return LogInWithGoogleFailure(
          'Account exists with different credentials.',
          code,
        );
      case 'invalid-credential':
        return LogInWithGoogleFailure(
          'The credential received is malformed or has expired.',
          code,
        );
      case 'operation-not-allowed':
        return LogInWithGoogleFailure(
          'Operation is not allowed.  Please contact support.',
          code,
        );
      case 'user-disabled':
        return LogInWithGoogleFailure(
          'This user has been disabled. Please contact support for help.',
          code,
        );
      case 'user-not-found':
        return LogInWithGoogleFailure(
          'Email is not found, please create an account.',
          code,
        );
      case 'wrong-password':
        return LogInWithGoogleFailure(
          'Incorrect password, please try again.',
          code,
        );
      case 'invalid-verification-code':
        return LogInWithGoogleFailure(
          'The credential verification code received is invalid.',
          code,
        );
      case 'invalid-verification-id':
        return LogInWithGoogleFailure(
          'The credential verification ID received is invalid.',
          code,
        );
      default:
        return const LogInWithGoogleFailure();
    }
  }

  /// The associated error message.
  final String message;
  final String code;
}

class LoginWithPhoneNumberFailure implements Exception {
  const LoginWithPhoneNumberFailure([
    this.message = 'An unknown exception occurred.',
    this.code = '',
  ]);

  factory LoginWithPhoneNumberFailure.fromCode(String code) {
    switch (code) {
      case 'invalid-phone-number':
        return LoginWithPhoneNumberFailure(
          'The provided phone number is not valid.',
          code,
        );
      case 'user-disabled':
        return LoginWithPhoneNumberFailure(
          'This user has been disabled. Please contact support for help.',
          code,
        );

      case 'code-not-sent':
        return LoginWithPhoneNumberFailure(
          'OTP not sent yet',
          code,
        );
      default:
        return const LoginWithPhoneNumberFailure();
    }
  }

  final String message;
  final String code;
}

/// Thrown during the logout process if a failure occurs.
class LogOutFailure implements Exception {}

/// {@template authentication_repository}
/// Repository which manages user authentication.
/// {@endtemplate}
class AuthenticationRepository {
  /// {@macro authentication_repository}
  AuthenticationRepository({
    CacheClient? cache,
    firebase_auth.FirebaseAuth? firebaseAuth,
    GoogleSignIn? googleSignIn,
  })  : _cache = cache ?? CacheClient(),
        _firebaseAuth = firebaseAuth ?? firebase_auth.FirebaseAuth.instance,
        _googleSignIn = googleSignIn ?? GoogleSignIn.standard();

  final CacheClient _cache;
  final firebase_auth.FirebaseAuth _firebaseAuth;
  final GoogleSignIn _googleSignIn;
  late StreamController<PhoneAuthCred> _phoneAuthCredStream;

  /// Whether or not the current environment is web
  /// Should only be overriden for testing purposes. Otherwise,
  /// defaults to [kIsWeb]
  @visibleForTesting
  bool isWeb = kIsWeb;

  /// User cache key.
  /// Should only be used for testing purposes.
  @visibleForTesting
  static const userCacheKey = '__user_cache_key__';

  /// Stream of [User] which will emit the current user when
  /// the authentication state changes.
  ///
  /// Emits [User.empty] if the user is not authenticated.
  Stream<User> get user {
    return _firebaseAuth.authStateChanges().map((firebaseUser) {
      final user = firebaseUser == null ? User.empty : firebaseUser.toUser;
      _cache.write(key: userCacheKey, value: user);
      return user;
    });
  }

  Stream<PhoneAuthCred> get phoneAuthCredential => _phoneAuthCredStream.stream;

  /// Returns the current cached user.
  /// Defaults to [User.empty] if there is no cached user.
  User get currentUser {
    return _cache.read<User>(key: userCacheKey) ?? User.empty;
  }

  /// Creates a new user with the provided [email] and [password].
  ///
  /// Throws a [SignUpWithEmailAndPasswordFailure] if an exception occurs.
  Future<void> signUp({required String email, required String password}) async {
    try {
      await _firebaseAuth.createUserWithEmailAndPassword(
        email: email,
        password: password,
      );
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw SignUpWithEmailAndPasswordFailure.fromCode(e.code);
    } catch (_) {
      throw const SignUpWithEmailAndPasswordFailure();
    }
  }

  /// Starts the Sign In with Google Flow.
  ///
  /// Throws a [LogInWithGoogleFailure] if an exception occurs.
  Future<void> logInWithGoogle() async {
    try {
      late final firebase_auth.AuthCredential credential;
      if (isWeb) {
        final googleProvider = firebase_auth.GoogleAuthProvider();
        final userCredential = await _firebaseAuth.signInWithPopup(
          googleProvider,
        );
        credential = userCredential.credential!;
      } else {
        final googleUser = await _googleSignIn.signIn();
        final googleAuth = await googleUser!.authentication;
        credential = firebase_auth.GoogleAuthProvider.credential(
          accessToken: googleAuth.accessToken,
          idToken: googleAuth.idToken,
        );
      }

      await _firebaseAuth.signInWithCredential(credential);
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw LogInWithGoogleFailure.fromCode(e.code);
    } catch (_) {
      throw const LogInWithGoogleFailure();
    }
  }

  /// Signs in with the provided [email] and [password].
  ///
  /// Throws a [LogInWithEmailAndPasswordFailure] if an exception occurs.
  Future<void> logInWithEmailAndPassword({
    required String email,
    required String password,
  }) async {
    try {
      await _firebaseAuth.signInWithEmailAndPassword(
        email: email,
        password: password,
      );
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw LogInWithEmailAndPasswordFailure.fromCode(e.code);
    } catch (_) {
      throw const LogInWithEmailAndPasswordFailure();
    }
  }

  Future<void> logInInWithPhoneNumber({
    required String countryCode,
    required String phoneNumber,
    bool? retry,
  }) async {
    _phoneAuthCredStream = StreamController<PhoneAuthCred>();
    final resendToken = (await _phoneAuthCredStream.stream.isEmpty)
        ? null
        : (await _phoneAuthCredStream.stream.last).resendToken;
    try {
      await _firebaseAuth.verifyPhoneNumber(
        phoneNumber: '+$countryCode$phoneNumber',
        verificationCompleted:
            (firebase_auth.PhoneAuthCredential credential) async {
          if (!_phoneAuthCredStream.isClosed) {
            _phoneAuthCredStream
                .add(PhoneAuthCred(smsCode: credential.smsCode ?? ''));
          }
          await _firebaseAuth.signInWithCredential(credential).then((_) {
            if (!_phoneAuthCredStream.isClosed) {
              _phoneAuthCredStream.close();
            }
          });
        },
        verificationFailed: (firebase_auth.FirebaseException exception) {
          if (!_phoneAuthCredStream.isClosed) {
            _phoneAuthCredStream.close();
          }
          throw LoginWithPhoneNumberFailure(exception.code);
        },
        codeSent: (String verificationId, int? resendToken) {
          if (!_phoneAuthCredStream.isClosed) {
            _phoneAuthCredStream.add(
              PhoneAuthCred(
                verificationId: verificationId,
                codeSent: true,
                resendToken: resendToken,
              ),
            );
          }
        },
        codeAutoRetrievalTimeout: (String verificationId) {
          if (!_phoneAuthCredStream.isClosed) {
            _phoneAuthCredStream.add(
              PhoneAuthCred(verificationId: verificationId, timedOut: true),
            );
          }
        },
        forceResendingToken: resendToken,
      );
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw LoginWithPhoneNumberFailure.fromCode(e.code);
    } catch (_) {
      throw const LoginWithPhoneNumberFailure();
    }
  }

  Future<bool> verifyOtp({required String smsCode}) async {
    try {
      if (await _phoneAuthCredStream.stream.isEmpty) {
        throw LoginWithPhoneNumberFailure.fromCode('code-not-sent');
      }
      final verificationId =
          (await _phoneAuthCredStream.stream.last).verificationId;

      final credential = await _firebaseAuth.signInWithCredential(
        firebase_auth.PhoneAuthProvider.credential(
          verificationId: verificationId,
          smsCode: smsCode,
        ),
      );

      return credential.user != null;
    } on firebase_auth.FirebaseAuthException catch (e) {
      throw LoginWithPhoneNumberFailure.fromCode(e.code);
    } catch (_) {
      throw const LoginWithPhoneNumberFailure();
    }
  }

  /// Signs out the current user which will emit
  /// [User.empty] from the [user] Stream.
  ///
  /// Throws a [LogOutFailure] if an exception occurs.
  Future<void> logOut() async {
    try {
      await Future.wait([
        _firebaseAuth.signOut(),
        _googleSignIn.signOut(),
      ]);
    } catch (_) {
      throw LogOutFailure();
    }
  }
}

extension on firebase_auth.User {
  User get toUser {
    return User(id: uid, email: email, name: displayName, photo: photoURL);
  }
}
