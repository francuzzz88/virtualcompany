package ru.petrov.virtualcompany.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import ru.petrov.virtualcompany.service.JwtMangerJJwtImpl;

import java.io.IOException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@SpringBootTest
class JwtAuthenticationFilterTest {

    private MockHttpServletRequest mockRequest;
    private MockHttpServletResponse mockResponse;
    private MockFilterChain mockFilterChain;
    private User user;
    private JwtAuthenticationFilter filter;
    private UsernamePasswordAuthenticationToken authentication;

    @MockBean
    private JwtMangerJJwtImpl jwtManager;

    @MockBean
    private AuthenticationManager authenticationManager;

    @BeforeEach
    void setUp() {
        mockRequest = new MockHttpServletRequest();
        mockResponse = new MockHttpServletResponse();
        mockFilterChain = new MockFilterChain();
        filter = new JwtAuthenticationFilter(authenticationManager, jwtManager);

        user = (User) User.builder()
                .username("test")
                .password("12345")
                .authorities("TADMIN", "TUSER")
                .build();

        authentication =
                new UsernamePasswordAuthenticationToken(user, null);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);

        when(jwtManager.generatedJwtAccessToken(user)).thenReturn("testAccessToken");
        when(jwtManager.generatedJwtRefreshToken(user)).thenReturn("testRefreshToken");

    }

    @Test
    void attemptAuthentication() {

        mockRequest.setParameter("username", "test");
        mockRequest.setParameter("password", "test");

        Authentication expected = filter.attemptAuthentication(mockRequest, mockResponse);
        assertNotNull(expected);
        assertEquals(expected.getPrincipal(), user);

    }


    @Test
    void successfulAuthentication() throws IOException {

        filter.successfulAuthentication(mockRequest, mockResponse, mockFilterChain, authentication);

        assertEquals(mockResponse.getContentType(), MediaType.APPLICATION_JSON_VALUE);
        var outputStream = mockResponse.getContentAsString();
        HashMap hashMap = new ObjectMapper().readValue(outputStream, HashMap.class);
        assertTrue(hashMap.containsKey("access-token"));
        assertTrue(hashMap.containsKey("refresh-token"));
        assertEquals(hashMap.get("access-token"), "testAccessToken");
        assertEquals(hashMap.get("refresh-token"), "testRefreshToken");
    }
}