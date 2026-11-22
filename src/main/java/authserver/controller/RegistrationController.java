package authserver.controller;

import authserver.service.OidcStoreService;
import authserver.service.UserService;
import authserver.service.UserService.RegistrationException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Cadastro de usuários NO servidor de autorização: é aqui (e só aqui) que a senha é criada e guardada.
 * Depois de cadastrado, o usuário entra em qualquer aplicação pelo fluxo OIDC normal.
 */
@Controller
@RequiredArgsConstructor
public class RegistrationController {

    private static final Logger log = LoggerFactory.getLogger(RegistrationController.class);

    private final UserService userService;
    private final OidcStoreService store;

    /** URL FIXA (configuração), nunca vinda do request: evita open redirect. */
    @Value("${oidc.app-login-url}")
    private String appLoginUrl;

    @GetMapping("/register")
    public String form(Model model) {
        model.addAttribute("appLoginUrl", appLoginUrl);
        return "register";
    }

    @PostMapping("/register")
    public String submit(@RequestParam(required = false) String username,
                         @RequestParam(required = false) String name,
                         @RequestParam(required = false) String email,
                         @RequestParam(required = false) String password,
                         @RequestParam(required = false) String confirm,
                         HttpServletRequest request, HttpServletResponse response, Model model) {

        model.addAttribute("appLoginUrl", appLoginUrl);

        if (!store.allowRegistration(request.getRemoteAddr())) {
            log.warn("Cadastro bloqueado por rate limiting: ip={}", request.getRemoteAddr());
            response.setStatus(429);
            model.addAttribute("erroCadastro", "Muitos cadastros a partir deste endereço. Tente mais tarde.");
            return "register";
        }
        try {
            userService.register(username, name, email, password, confirm);
            log.info("Novo usuário cadastrado: {}", username == null ? "" : username.trim().toLowerCase());
            model.addAttribute("sucesso", true);
        } catch (RegistrationException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            model.addAttribute("erroCadastro", e.getMessage());
            // repopula os campos (NUNCA a senha)
            model.addAttribute("form_username", username);
            model.addAttribute("form_name", name);
            model.addAttribute("form_email", email);
        }
        return "register";
    }
}
