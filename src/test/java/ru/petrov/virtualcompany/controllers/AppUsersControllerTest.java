package ru.petrov.virtualcompany.controllers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import ru.petrov.virtualcompany.repositoryes.AppUserRepository;
import ru.petrov.virtualcompany.service.AppUserService;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class AppUsersControllerTest {

    @Autowired
    private WebApplicationContext context;

    @MockBean
    private AppUserService userService;

    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {
        var bean = context.getBean(AppUserRepository.class);
        bean.deleteAll();
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }


    @Test
    @WithMockUser(username = "admin", password = "1234", authorities = {"USER", "ADMIN"})
    public void aboutReturnsUser() throws Exception {
        mockMvc.perform(get("/users"))
                .andExpect(status().isOk());
    }

    @Test()
    @WithMockUser(username = "admin", password = "1234", authorities = {"USER", "ADMIN"})
    public void shouldAddNewUser() throws Exception {

        String content = "{\"username\":\"test1\",\"password\":\"1234\",\"email\":\"user5@email.ru\"}";
        mockMvc.perform(post("/users").contentType(MediaType.APPLICATION_JSON).content(content))
                .andExpect(status().isOk());

    }

    @Test
    @WithMockUser
    public void shouldReturnForbidden() throws Exception {
        String content = "{\"username\":\"test2\",\"password\":\"1234\",\"email\":\"user5@email.ru\"}";
        mockMvc.perform(post("/users").contentType(MediaType.APPLICATION_JSON).content(content))
                .andExpect(status().isForbidden());
    }
    @Test
    public void shouldReturnUnauthorized() throws Exception {
        String content = "{\"username\":\"test3\",\"password\":\"1234\",\"email\":\"user5@email.ru\"}";
        mockMvc.perform(post("/users").contentType(MediaType.APPLICATION_JSON).content(content))
                .andExpect(status().isUnauthorized());
    }
    @Test()
    @WithMockUser(username = "user", password = "1234", authorities = {"USER"})
    public void shouldReturnForbiddenWhenPostUser() throws Exception {

        String content = "{\"username\":\"test1\",\"password\":\"1234\",\"email\":\"user5@email.ru\"}";
        mockMvc.perform(post("/users").contentType(MediaType.APPLICATION_JSON).content(content))
                .andExpect(status().isForbidden());

    }

    @Test
    @WithMockUser
    public void shouldReturnsForbidden() throws Exception {
        mockMvc.perform(get("/users"))
                .andExpect(status().isForbidden());
    }

    @Test
    public void shouldReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "user", password = "1234", authorities = {"ADMIN"})
    public void shouldReturnOkWhenСallingAdminAddRole() throws Exception {
        String addRole = "{\"roleName\":\"ROLENAME\"}";
        mockMvc.perform(post("/role").contentType(MediaType.APPLICATION_JSON).content(addRole))
                .andExpect(status().isOk());
    }
    @Test
    @WithMockUser(username = "user", password = "1234", authorities = {"USER"})
    public void shouldReturnForbiddenWhenСallingUserAddRole() throws Exception {
        String addRole = "{\"roleName\":\"ROLENAME\"}";
        mockMvc.perform(post("/role").contentType(MediaType.APPLICATION_JSON).content(addRole))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "user", password = "1234", authorities = {"ADMIN"})
    public void shouldReturnOkWhenСallingAdminAddRoleToUser() throws Exception {
        Mockito.doAnswer(i -> null).when(userService).addRoleToUser("test", "ROLENAME");
        String addRoleToUser = "{\"username\":\"test\",\"rolName\":\"ROLENAME\"}";
        mockMvc.perform(post("/addroletouser").contentType(MediaType.APPLICATION_JSON).content(addRoleToUser))
                .andExpect(status().isOk());
    }
    @Test
    @WithMockUser(username = "user", password = "1234", authorities = {"USER"})
    public void shouldReturnForbiddenWhenСallingUserAddRoleToUser() throws Exception {
        String addRoleToUser = "{\"username\":\"test\",\"rolName\":\"ROLENAME\"}";
        mockMvc.perform(post("/addroletouser").contentType(MediaType.APPLICATION_JSON).content(addRoleToUser))
                .andExpect(status().isForbidden());
    }
}
