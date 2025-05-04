package com.webauthn.app.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.webauthn.app.authenticator.Authenticator;
import com.webauthn.app.user.AppUser;
import com.webauthn.app.utility.Utility;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpSession;
import java.io.IOException;

import static com.webauthn.app.utility.Utility.log;

@Controller
public class AuthController {

    private final RelyingParty relyingParty;
    private final RegistrationService service;

    AuthController(RegistrationService service, RelyingParty relyingParty) {
        this.relyingParty = relyingParty;
        this.service = service;
    }

    @GetMapping("/")
    public String welcome() {
        return "index";
    }

    @GetMapping("/register")
    public String registerUser(Model model) {
        return "register";
    }

    @PostMapping("/register")
    @ResponseBody
    public String newUserRegistration(
            @RequestParam String username,
            @RequestParam String display,
            HttpSession session
    ) {
        log("newUserRegistration: Registering user: " + username + ", display: " + display);
        AppUser existingUser = service.getUserRepo().findByUsername(username);
        if (existingUser == null) {
            log("newUserRegistration: Creating new user: " + username);
            UserIdentity userIdentity = UserIdentity.builder()
                    .name(username)
                    .displayName(display)
                    .id(Utility.generateRandom(32))
                    .build();

            log("newUserRegistration: User identity: " + userIdentity);
            AppUser saveUser = new AppUser(userIdentity);
            service.getUserRepo().save(saveUser);
            log("newUserRegistration: Saved new user");
            return newAuthRegistration(saveUser, session);
        } else {
            log("newUserRegistration: User already exists: " + username);
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username " + username + " already exists. Choose a new name.");
        }
    }

    @PostMapping("/registerauth")
    @ResponseBody
    public String newAuthRegistration(
            @RequestParam AppUser user,
            HttpSession session
    ) {
        log("newAuthRegistration: Called newAuthRegistration for user: " + user.getUsername());
        AppUser existingUser = service.getUserRepo().findByHandle(user.getHandle());
        if (existingUser != null) {
            log("newAuthRegistration: User exists: " + user.getUsername());
            UserIdentity userIdentity = user.toUserIdentity();
            log("newAuthRegistration: User identity: " + userIdentity);
            StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                    .user(userIdentity)
                    .build();

            log("newAuthRegistration: Registration options: " + registrationOptions);

            PublicKeyCredentialCreationOptions registration = relyingParty.startRegistration(registrationOptions);
            log("newAuthRegistration: Registration: " + registration);
            session.setAttribute(userIdentity.getName(), registration);
            try {
                String returnJson = registration.toCredentialsCreateJson();
                log("newAuthRegistration: Registration JSON: " + returnJson);
                return returnJson;
            } catch (JsonProcessingException e) {
                log("newAuthRegistration: JsonProcessingException: " + e.getMessage());
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error processing JSON.", e);
            }
        } else {
            log("newAuthRegistration: User does not exist: " + user.getUsername());
            throw new ResponseStatusException(HttpStatus.CONFLICT, "User " + user.getUsername() + " does not exist. Please register.");
        }
    }

    @PostMapping("/finishauth")
    @ResponseBody
    public ModelAndView finishRegistration(
            @RequestParam String credential,
            @RequestParam String username,
            @RequestParam String credname,
            HttpSession session
    ) {
        try {
            log("finishRegistration: Starting finishRegistration for user: " + username);
            AppUser user = service.getUserRepo().findByUsername(username);
            log("finishRegistration: user.getUsername(): " + user.getUsername());
            PublicKeyCredentialCreationOptions requestOptions = (PublicKeyCredentialCreationOptions) session.getAttribute(user.getUsername());
            log("finishRegistration: Request options: " + requestOptions);
            if (requestOptions != null) {
                log("finishRegistration: Request options not null");
                PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                        PublicKeyCredential.parseRegistrationResponseJson(credential);
                log("finishRegistration: Parsed credential: " + pkc);
                FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                        .request(requestOptions)
                        .response(pkc)
                        .build();
                log("finishRegistration: Finish registration options: " + options);
                RegistrationResult result = relyingParty.finishRegistration(options);
                log("finishRegistration: Registration result: " + result);
                Authenticator savedAuth = new Authenticator(result, pkc.getResponse(), user, credname);
                log("finishRegistration: Saved Authenticator: " + savedAuth);
                service.getAuthRepository().save(savedAuth);
                log("finishRegistration: Saved Authenticator to repository");
                return new ModelAndView("redirect:/login", HttpStatus.SEE_OTHER);
            } else {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Cached request expired. Try to register again!");
            }
        } catch (RegistrationFailedException e) {
            log("finishRegistration: Registration failed: " + e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration failed.", e);
        } catch (IOException e) {
            log("finishRegistration: IOException: " + e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to save credenital, please try again!", e);
        }
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @PostMapping("/login")
    @ResponseBody
    public String startLogin(
            @RequestParam String username,
            HttpSession session
    ) {
        log("Starting login for user: " + username);
        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(username)
                .build());
        try {
            session.setAttribute(username, request);
            return request.toCredentialsGetJson();
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/welcome")
    public String finishLogin(
            @RequestParam String credential,
            @RequestParam String username,
            Model model,
            HttpSession session
    ) {
        log("finishLogin: Starting finishLogin for user: " + username);
        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc;
            pkc = PublicKeyCredential.parseAssertionResponseJson(credential);
            AssertionRequest request = (AssertionRequest) session.getAttribute(username);
            AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build());
            if (result.isSuccess()) {
                model.addAttribute("username", username);
                return "welcome";
            } else {
                return "index";
            }
        } catch (Exception e) {
            log("finishLogin: Exception: " + e.getMessage());
            throw new RuntimeException("Authentication failed", e);
        }
    }
}
