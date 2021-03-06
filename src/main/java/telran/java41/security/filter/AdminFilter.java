package telran.java41.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;
import telran.java41.security.context.SecurityContext;
import telran.java41.security.context.User;

@Service
@Order(20)
@AllArgsConstructor
public class AdminFilter implements Filter {
	
	SecurityContext context;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;	
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			User user = context.getUser(request.getUserPrincipal().getName());
			if(!user.getRoles().contains("Administrator".toUpperCase())) {
				response.sendError(403);
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkEndPoint(String method, String path) {

		return path.matches("/account/user/\\w+/role/\\w+/?");
	}

}
