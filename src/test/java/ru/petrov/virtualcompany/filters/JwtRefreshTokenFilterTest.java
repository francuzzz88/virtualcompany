package ru.petrov.virtualcompany.filters;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import ru.petrov.virtualcompany.service.AppUserService;
import ru.petrov.virtualcompany.service.JwtMangerJJwtImpl;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

@SpringBootTest
class JwtRefreshTokenFilterTest {

    private MockHttpServletRequest mockRequest;
    private MockHttpServletResponse mockResponse;
    private MockFilterChain mockFilterChain;
    private User user;

    @MockBean
    private JwtMangerJJwtImpl jwtManager;

    @MockBean
    private AppUserService userService;

    @Autowired
    private JwtRefreshTokenFilter jwtRefreshTokenFilter;

    @BeforeEach
    void setUp() {
        mockRequest = new MockHttpServletRequest();
        mockResponse = new MockHttpServletResponse();
        mockFilterChain = new MockFilterChain();

        user = (User) User.builder()
                .username("test")
                .password("12345")
                .authorities("TADMIN", "TUSER")
                .build();

        mockRequest.setServletPath("/refresh");

        when(jwtManager.verifyRefreshToken("token")).thenReturn(user);
        when(jwtManager.generatedJwtRefreshToken(user)).thenReturn("token");

        SecurityContextHolder.clearContext();
    }

    @Test
    void testJwtFilter() throws ServletException, IOException {
        MockFilterChain mockFilterChainSpy = spy(mockFilterChain);
        jwtRefreshTokenFilter.doFilter(mockRequest, mockResponse, mockFilterChainSpy);

        verify(mockFilterChainSpy, times(1)).doFilter(mockRequest, mockResponse);
    }

    @Test
    void shouldReturnAuthenticationInSecurityContext() throws ServletException, IOException {

        when(userService.loadUserByUsername("test")).thenReturn(user);

        String tokenValue = "Bearer " + jwtManager.generatedJwtRefreshToken(user);
        mockRequest.addHeader("Authorization", tokenValue);

        jwtRefreshTokenFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();

        assertEquals(authentication.getPrincipal(), "test");
        assertEquals(authentication.getAuthorities().size(), 2);

    }

    @Test
    void shouldFilterContinuesToNextFilterWhenRequestHasNoToken() throws ServletException, IOException {
        MockFilterChain mockFilterChainSpy = spy(mockFilterChain);
        MockHttpServletRequest requestWithoutToken = new MockHttpServletRequest();

        jwtRefreshTokenFilter.doFilter(requestWithoutToken, mockResponse, mockFilterChainSpy);
        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();

        verify(mockFilterChainSpy, times(1)).doFilter(requestWithoutToken, mockResponse);
        assertNull(authentication);
    }

    @Test
    void shouldFilterContinuesToNextFilterWhenBadTokenSignature() throws ServletException, IOException {

        mockRequest.addHeader("Authorization", "Bearer token");
        when(jwtManager.verifyRefreshToken("token")).thenThrow(SignatureException.class);
        jwtRefreshTokenFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();

        assertNull(authentication);
        assertEquals(mockResponse.getStatus(), HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void shouldFilterContinuesToNextFilterWhenTokenExpiration() throws ServletException, IOException {

        mockRequest.addHeader("Authorization", "Bearer token");

        when(jwtManager.verifyRefreshToken("token")).thenThrow(ExpiredJwtException.class);

        jwtRefreshTokenFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();

        assertNull(authentication);
        assertEquals(mockResponse.getStatus(), HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void shouldFilterContinuesToNextFilterWhenAuthorizationIsNull() throws ServletException, IOException {

        mockRequest.addHeader("Authorization", "");

        jwtRefreshTokenFilter.doFilter(mockRequest, mockResponse, mockFilterChain);

        Authentication authentication = SecurityContextHolder.getContext()
                .getAuthentication();

        assertNull(authentication);
        assertEquals(mockResponse.getStatus(), HttpServletResponse.SC_OK);
    }

}