package com.example.learnspringsecuirty.controllers;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TodoController {
  private static final List<Todo> TODOS_LIST =
      List.of(new Todo("in28minutes", "Learn AWS"), new Todo("in28minutes", "Get AWS Certified"));
  private Logger logger = LoggerFactory.getLogger(getClass());

  @GetMapping("/todos")
  public List<Todo> retrieveAllTodos() {
    return TODOS_LIST;
  }

  @GetMapping("csrftoken")
  public CsrfToken csrf(HttpServletRequest request) {
    return (CsrfToken) request.getAttribute("_csrf");
  }

  @GetMapping("/users/{userName}/todos")
  public Todo retrieveTodosForSpecificUser(@PathVariable("userName") String username) {
    return TODOS_LIST.get(0);
  }

  // This will fail if csrf filter is enabled (its enabled by default)
  // in DefaultSecurityFilterChain
  @PostMapping("/users/{username}/todos")
  public String createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo) {
    logger.info("Create {} for {}", todo, username);
    // TODOS_LIST.add(todo);
    return "added";
  }
}

record Todo(String username, String description) {}
