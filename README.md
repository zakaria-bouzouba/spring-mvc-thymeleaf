# Projet Spring MVC avec Thymeleaf

## 🚀 Introduction

Ce dépôt contient une application pédagogique développée avec **Spring Boot** et **Thymeleaf**.  
L’objectif est de construire une application web simple permettant la **gestion de produits** (affichage, ajout et
suppression) avec un système **d’authentification et d’autorisation** via **Spring Security**.

L’application illustre l’intégration de plusieurs modules Spring : MVC, JPA, Validation, Security, et l’utilisation
d’une base **H2 en mémoire**.  
Le tout est présenté dans une interface web dynamique grâce à **Thymeleaf** et **Bootstrap 5**.

---

## 🗂️ Structure du projet

```
spring-mvc-thymeleaf/
├── src/main/java/net/zakaria/springmvcthymeleaf/
│   ├── SpringMvcThymeleafApplication.java
│   ├── entities/
│   │   └── Product.java
│   ├── repository/
│   │   └── ProductRepository.java
│   ├── security/
│   │   └── SecurityConfig.java
│   └── web/
│       └── ProductController.java
│
├── src/main/resources/
│   ├── templates/
│   │   ├── layout1.html
│   │   ├── login.html
│   │   ├── new-product.html
│   │   ├── notAuthorized.html
│   │   └── products.html
│   └── application.properties
│
└── pom.xml
```

---

## 🛠️ Technologies utilisées

| Technologie                       | Version / Détail    | Description courte                                              |
|-----------------------------------|---------------------|-----------------------------------------------------------------|
| ☕ **Java**                        | 21                  | Langage principal du projet                                     |
| 🚀 **Spring Boot**                | 3.4.5               | Framework principal facilitant la configuration et le démarrage |
| 🧩 **Spring MVC**                 | —                   | Gestion du modèle MVC et du routage des contrôleurs             |
| 🔐 **Spring Security**            | —                   | Authentification et autorisation basées sur les rôles           |
| 🗃️ **Spring Data JPA**           | —                   | Accès aux données et gestion ORM avec Hibernate                 |
| 🎨 **Thymeleaf** + Layout Dialect | —                   | Moteur de template HTML avec système de layout                  |
| 💅 **Bootstrap**                  | 5.3.5               | Framework CSS pour la mise en page responsive                   |
| 🧠 **H2 Database**                | —                   | Base de données en mémoire pour le développement                |
| ⚙️ **Lombok**                     | 1.18.38 (optionnel) | Génération automatique de code (getters, setters, etc.)         |

---

## 🧠 Code source et explications

---

### 1) `Product.java`

```java
package net.zakaria.springmvcthymeleaf.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.*;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
@Builder
public class Product {
    @Id
    @GeneratedValue
    private Long id;
    @NotEmpty
    @Size(min = 3, max = 50)
    private String name;
    @Min(0)
    private double price;
    @Min(1)
    private double quantity;
}
```

**Explication :**

- `@Entity` : marque la classe comme entité JPA persistable.
- `@Id` + `@GeneratedValue` : identifiant primaire auto‑généré.
- Validation :
    - `@NotEmpty` + `@Size(min=3,max=50)` pour le nom (évite noms vides ou trop courts/longs).
    - `@Min(0)` pour le prix (non négatif).
    - `@Min(1)` pour la quantité (au moins 1).
- Lombok (`@Getter`, `@Setter`, `@Builder`, etc.) réduit le code boilerplate.

---

### 2) `ProductRepository.java`

```java
package net.zakaria.springmvcthymeleaf.repository;

import net.zakaria.springmvcthymeleaf.entities.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long> {
}
```

**Explication :**

- Interface qui étend `JpaRepository` : fournit les méthodes CRUD (`save`, `findAll`, `findById`, `deleteById`, ...)
  automatiquement.
- Aucune implémentation nécessaire ; Spring Data génère l'implémentation à l'exécution.

---

### 3) `SecurityConfig.java`

```java
package net.zakaria.springmvcthymeleaf.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        return new InMemoryUserDetailsManager(
                User.withUsername("user1").password(passwordEncoder().encode("1234")).roles("USER").build(),
                User.withUsername("user2").password(passwordEncoder().encode("1234")).roles("USER").build(),
                User.withUsername("admin").password(passwordEncoder().encode("1234")).roles("USER", "ADMIN").build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .formLogin(fl -> fl.loginPage("/login").permitAll())
                .csrf(Customizer.withDefaults())
                .authorizeHttpRequests(ar -> ar.requestMatchers("/public/**", "/webjars/**").permitAll())
                .authorizeHttpRequests(ar -> ar.anyRequest().authenticated())
                .exceptionHandling(eh -> eh.accessDeniedPage("/notAuthorized"))
                .build();
    }
}
```

**Explication :**

- `PasswordEncoder` : utilisation de BCrypt (bon compromis sécurité/usages pédagogiques).
- `InMemoryUserDetailsManager` : définit trois comptes en mémoire :
    - `user1`, `user2` → rôle `USER`
    - `admin` → rôles `USER` et `ADMIN`
- `SecurityFilterChain` :
    - Page de connexion : `/login` (accessible sans auth).
    - Toutes les autres routes nécessitent une authentification.
    - Ressources publiques `/public/**` et `/webjars/**` sont autorisées sans authentification.
    - En cas de refus d'accès, redirection vers `/notAuthorized`.

---

### 4) `ProductController.java`

```java
package net.zakaria.springmvcthymeleaf.web;

import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import net.zakaria.springmvcthymeleaf.entities.Product;
import net.zakaria.springmvcthymeleaf.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;
import java.util.Optional;

@Controller
public class ProductController {
    @Autowired
    private ProductRepository productRepository;

    @GetMapping("/user/index")
    @PreAuthorize("hasRole('USER')")
    public String index(Model model) {
        List<Product> products = productRepository.findAll();
        model.addAttribute("productList", products);
        return "products";
    }

    @GetMapping("/")
    public String home() {
        return "redirect:/user/index";
    }

    @PostMapping("/admin/delete")
    @PreAuthorize("hasRole('ADMIN')")
    public String delete(@RequestParam(name = "id") Long id) {
        productRepository.deleteById(id);
        return "redirect:/user/index";
    }

    @GetMapping("/admin/newProduct")
    @PreAuthorize("hasRole('ADMIN')")
    public String newProduct(Model model) {
        model.addAttribute("product", new Product());
        return "new-product";
    }

    @GetMapping("/admin/edit/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String editProductForm(@PathVariable Long id, Model model, RedirectAttributes redirectAttributes) {
        Optional<Product> opt = productRepository.findById(id);
        if (opt.isEmpty()) {
            redirectAttributes.addFlashAttribute("errorMessage", "Product not found");
            return "redirect:/user/index";
        }
        model.addAttribute("product", opt.get());
        return "new-product";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/admin/saveProduct")
    public String saveProduct(@Valid Product product, BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) return "new-product";
        productRepository.save(product);
        return "redirect:/user/index";
    }

    @GetMapping("/notAuthorized")
    public String notAuthorized() {
        return "notAuthorized";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "login";
    }
}
```

**Explication :**

- `/user/index` → affichage de tous les produits (rôle USER ou ADMIN)
- `/admin/newProduct` → formulaire d’ajout
- `/admin/edit/{id}` → formulaire de modification (rempli automatiquement)
- `/admin/saveProduct` → ajout ou édition selon présence de l’ID
- `/admin/delete` → suppression du produit
- Validation assurée par `@Valid` + `BindingResult`

---

### 5) `SpringMvcThymeleafApplication.java`

```java
package net.zakaria.springmvcthymeleaf;

import net.zakaria.springmvcthymeleaf.entities.Product;
import net.zakaria.springmvcthymeleaf.repository.ProductRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SpringMvcThymeleafApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringMvcThymeleafApplication.class, args);
    }

    @Bean
    public CommandLineRunner start(ProductRepository productRepository) {
        return args -> {
            productRepository.save(Product.builder().name("Computer").price(5400).quantity(12).build());
            productRepository.save(Product.builder().name("Printer").price(1200).quantity(11).build());
            productRepository.save(Product.builder().name("Smart Phone").price(12000).quantity(33).build());
            productRepository.findAll().forEach(System.out::println);
        };
    }
}
```

**Explication :**

- Point d'entrée de l'application annoté `@SpringBootApplication`.
- `CommandLineRunner` : injecte trois produits d'exemple au démarrage (utile pour démonstration et tests).

---

### 6) `application.properties`

```properties
spring.application.name=spring-mvc-thymeleaf
spring.datasource.url=jdbc:h2:mem:products-db
spring.datasource.username=sa
spring.datasource.password=
spring.jpa.hibernate.ddl-auto=update
server.port=8094
spring.h2.console.enabled=true
```

**Explication :**

- Configuration d'une base **H2 en mémoire** (`jdbc:h2:mem:products-db`).
- `spring.jpa.hibernate.ddl-auto=update` : synchronise le schéma automatiquement (utile en dev).
- Serveur sur le port **8094**.
- Console H2 activée (accès via `/h2-console` par défaut).

---

### 7) Templates Thymeleaf

#### `layout1.html`

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org"
      xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
      xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head>
    <meta charset="UTF-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <title th:text="${pageTitle} ?: 'Products Management'">Products</title>
    <link rel="stylesheet" href="/webjars/bootstrap/5.3.5/css/bootstrap.min.css"/>
    <style>
        body {
            font-family: "Georgia", serif;
            background: #f6f7fb;
        }

        .navbar-brand {
            font-weight: 600;
            letter-spacing: .5px;
        }

        .page-header {
            margin-top: 1rem;
            margin-bottom: 1rem;
        }

        .card-compact {
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
        }

        .table-actions button {
            margin-right: .35rem;
        }

        .muted {
            color: #6c757d;
        }
    </style>
    <script src="/webjars/bootstrap/5.3.5/js/bootstrap.bundle.js"></script>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark" style="background:#1f497d;">
    <div class="container">
        <a class="navbar-brand" th:href="@{/}">Product Management</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navMain">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navMain">
            <ul class="navbar-nav ms-auto">
                <li class="nav-item dropdown">
                    <a class="nav-link dropdown-toggle" href="#" id="userMenu" role="button" data-bs-toggle="dropdown">
                        <span sec:authentication="name">User</span>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userMenu">
                        <li><a class="dropdown-item" th:href="@{/logout}">Logout</a></li>
                    </ul>
                </li>
            </ul>
        </div>
    </div>
</nav>

<main class="container">
    <header class="page-header">
        <div class="d-flex justify-content-between align-items-center">
            <div>
                <h1 th:text="${pageTitle} ?: 'Products'">Products</h1>
                <p class="muted">Manage product catalog — add, edit or remove entries.</p>
            </div>
            <div>
                <div th:if="${successMessage}" class="alert alert-success" th:text="${successMessage}"></div>
                <div th:if="${errorMessage}" class="alert alert-danger" th:text="${errorMessage}"></div>
            </div>
        </div>
    </header>

    <div layout:fragment="content1"></div>

    <footer class="mt-5 mb-4 text-muted small">
        <div class="d-flex justify-content-between">
            <div>© <span th:text="${T(java.time.Year).now().value}"></span> Zakaria Bouzouba</div>
            <div>Spring Boot + Thymeleaf</div>
        </div>
    </footer>
</main>
</body>
</html>
```

**Explication :**

- Template principal (layout) utilisé par les autres vues (`layout:decorate="layout1"`).
- Barre de navigation Bootstrap, affichage du nom d'utilisateur via `sec:authentication="name"`.
- Fragment `content1` : emplacement pour injecter le contenu des pages enfants.

---

#### `login.html`

```html
<!DOCTYPE html>
<html lang="en"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
      layout:decorate="layout1">
<head>
    <meta charset="UTF-8"/>
    <title>Login</title>
</head>
<body>
<div class="p-3" layout:fragment="content1">
    <div class="row justify-content-center align-items-center" style="min-height:60vh;">
        <div class="col-12 col-sm-10 col-md-6 col-lg-4">
            <div class="card card-compact">
                <div class="card-header" style="background:#f1f5f9;">
                    <h5 class="mb-0">Sign in</h5>
                    <div class="muted small">Access the product management panel</div>
                </div>

                <div class="card-body">
                    <form th:action="@{/login}" method="post" class="mb-0">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input id="username" name="username" type="text"
                                   class="form-control" placeholder="Enter your username" autofocus>
                        </div>

                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input id="password" name="password" type="password"
                                   class="form-control" placeholder="Enter your password">
                        </div>

                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary" style="background:#1f497d">Log in</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
```

**Explication :**

- Formulaire très simple pour l'authentification.
- Soumis vers l'endpoint `/login` (Spring Security gère l'authentification par défaut).
- Page décorée automatiquement par `layout1.html`

---

#### `new-product.html`

```html
<!DOCTYPE html>
<html lang="en"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
      layout:decorate="layout1">
<head>
    <meta charset="UTF-8">
    <title th:text="${product.id} != null ? 'Edit product' : 'New product'">Product</title>
</head>
<body>
<div class="p-3" layout:fragment="content1">
    <div class="row justify-content-center">
        <div class="col-12 col-md-8">
            <div class="card card-compact">
                <div class="card-header">
                    <h5 class="mb-0" th:text="${product.id} != null ? 'Edit product' : 'New product'">New product</h5>
                </div>
                <div class="card-body">
                    <form th:action="@{/admin/saveProduct}" method="post" th:object="${product}">
                        <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>

                        <input type="hidden" th:if="${product.id != null}" th:field="*{id}"/>

                        <div class="mb-3">
                            <label class="form-label">Name</label>
                            <input class="form-control" type="text" th:field="*{name}" placeholder="Product name"/>
                            <div class="invalid-feedback d-block" th:if="${#fields.hasErrors('name')}"
                                 th:errors="*{name}"></div>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Price</label>
                            <input class="form-control" type="number" step="0.01" th:field="*{price}"
                                   placeholder="0.00"/>
                            <div class="invalid-feedback d-block" th:if="${#fields.hasErrors('price')}"
                                 th:errors="*{price}"></div>
                        </div>

                        <div class="mb-3">
                            <label class="form-label">Quantity</label>
                            <input class="form-control" type="number" th:field="*{quantity}" placeholder="0"/>
                            <div class="invalid-feedback d-block" th:if="${#fields.hasErrors('quantity')}"
                                 th:errors="*{quantity}"></div>
                        </div>

                        <div class="d-flex justify-content-between">
                            <a class="btn btn-outline-secondary" th:href="@{/user/index}">Back</a>
                            <button type="submit" class="btn btn-primary">Save</button>
                        </div>

                    </form>
                </div>
            </div>
        </div>
    </div>
</div>
</body>
</html>
```

**Explication :**

- Formulaire utilisé pour **l’ajout** et **la modification** grâce au même template
- Utilise `th:value` pour pré-remplir les champs en cas d'erreurs de validation.
- `th:errors` affiche les erreurs liées aux contraintes de validation.

---

#### `notAuthorized.html`

```html
<!DOCTYPE html>
<html lang="en"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
      layout:decorate="layout1"
>
<head>
    <meta charset="UTF-8">
    <title>Products</title>
</head>
<body>
<div class="p-3" layout:fragment="content1">
    <h3 class="text-danger">Not Authorized</h3>
</div>
</body>
</html>
```

**Explication :**

- Page simple affichant un message d'accès refusé.
- Renvoyée par la configuration de sécurité (`.accessDeniedPage("/notAuthorized")`).

---

#### `products.html`

```html
<!DOCTYPE html>
<html lang="en"
      xmlns:th="http://www.thymeleaf.org"
      xmlns:layout="http://www.ultraq.net.nz/thymeleaf/layout"
      xmlns:sec="http://www.thymeleaf.org/extras/spring-security"
      layout:decorate="layout1">
<head>
    <meta charset="UTF-8">
    <title>Products</title>
</head>
<body>
<div class="p-3" layout:fragment="content1">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <div>
            <h3 class="mb-0">List of all products</h3>
        </div>
        <div sec:authorize="hasRole('ADMIN')">
            <a class="btn btn-primary" th:href="@{/admin/newProduct}">New Product</a>
        </div>
    </div>

    <div class="card card-compact">
        <div class="card-body p-0">
            <table class="table table-hover mb-0">
                <thead class="table-light">
                <tr>
                    <th>ID</th>
                    <th>Name</th>
                    <th class="text-end">Price</th>
                    <th class="text-end">Quantity</th>
                    <th class="text-end" sec:authorize="hasRole('ADMIN')">Actions</th>
                </tr>
                </thead>
                <tbody>
                <tr th:each="p : ${productList}">
                    <td th:text="${p.id}">1</td>
                    <td th:text="${p.name}">Example</td>
                    <td class="text-end" th:text="${p.price}">0.0</td>
                    <td class="text-end" th:text="${p.quantity}">0</td>
                    <td class="text-end table-actions" sec:authorize="hasRole('ADMIN')">
                        <div sec:authorize="hasRole('ADMIN')" class="d-inline-flex">
                            <a th:href="@{|/admin/edit/${p.id}|}"
                               class="btn btn-sm me-1 btn-warning text-white">Edit</a>
                            <form th:action="@{/admin/delete}" method="post" th:object="${p}"
                                  onsubmit="return confirm('Delete product?');">
                                <input type="hidden" th:name="${_csrf.parameterName}" th:value="${_csrf.token}"/>
                                <input type="hidden" name="id" th:value="${p.id}"/>
                                <button type="submit" class="btn btn-sm btn-danger">Delete</button>
                            </form>
                        </div>
                    </td>
                </tr>
                <tr th:if="${#lists.isEmpty(productList)}">
                    <td colspan="5" class="text-center muted">No products found.</td>
                </tr>
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>
</html>
```

**Explication :**

- Tableau dynamique listant tous les produits
- Les actions Edit / Delete sont affichées uniquement pour le rôle ADMIN
- Protection CSRF intégrée dans les formulaires

---

### 8) `pom.xml`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.4.5</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>net.zakaria</groupId>
    <artifactId>spring-mvc-thymeleaf</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>spring-mvc-thymeleaf</name>
    <description>spring-mvc-thymeleaf</description>
    <url/>
    <licenses>
        <license/>
    </licenses>
    <developers>
        <developer/>
    </developers>
    <scm>
        <connection/>
        <developerConnection/>
        <tag/>
        <url/>
    </scm>
    <properties>
        <java.version>21</java.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.webjars</groupId>
            <artifactId>bootstrap</artifactId>
            <version>5.3.5</version>
        </dependency>
        <dependency>
            <groupId>nz.net.ultraq.thymeleaf</groupId>
            <artifactId>thymeleaf-layout-dialect</artifactId>
        </dependency>
        <dependency>
            <groupId>org.thymeleaf.extras</groupId>
            <artifactId>thymeleaf-extras-springsecurity6</artifactId>
        </dependency>

        <dependency>
            <groupId>com.h2database</groupId>
            <artifactId>h2</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>com.mysql</groupId>
            <artifactId>mysql-connector-j</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
            <optional>true</optional>
            <version>1.18.38</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <configuration>
                    <annotationProcessorPaths>
                        <path>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                            <version>1.18.38</version>
                        </path>
                    </annotationProcessorPaths>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
                <configuration>
                    <excludes>
                        <exclude>
                            <groupId>org.projectlombok</groupId>
                            <artifactId>lombok</artifactId>
                        </exclude>
                    </excludes>
                </configuration>
            </plugin>
        </plugins>
    </build>

</project>
```

**Explication :**

- Déclare les dépendances nécessaires : Spring Boot starters (web, thymeleaf, security, data‑jpa, validation), H2,
  Webjars Bootstrap, Thymeleaf layout dialect, Thymeleaf security extras, Lombok.
- Configure Java 21 comme version cible.
- Plugins Maven : compilation et Spring Boot Maven plugin.

---

## ▶️ Exécution

1. Compiler et exécuter :

```bash
mvn spring-boot:run
```

2. Ouvrir le navigateur : `http://localhost:8094`


3. Identifiants disponibles :

| Utilisateur | Mot de passe | Rôle        |
|-------------|--------------|-------------|
| user1       | 1234         | USER        |
| user2       | 1234         | USER        |
| admin       | 1234         | ADMIN, USER |

---

## 📸 Captures d'écran

![Login](screenshots/Screenshot 2025-11-26 111911.jpg)
![ProductsAdmin](screenshots/Screenshot 2025-11-26 111952.jpg)
![Add](screenshots/Screenshot 2025-11-26 112110.jpg)
![Edit](screenshots/Screenshot 2025-11-26 112256.jpg)
![Delete](screenshots/Screenshot 2025-11-26 112323.jpg)
![ProductsUser](screenshots/Screenshot 2025-11-26 112348.jpg)

---

## 🧾 Conclusion

Ce projet constitue une excellente base pour comprendre :

- la structure d’un projet **Spring Boot MVC**,
- la sécurisation des routes avec **Spring Security**,
- la validation des formulaires et la persistance des données avec **JPA**,
- et la mise en page dynamique grâce à **Thymeleaf** et **Bootstrap**.

Il illustre de manière claire le fonctionnement complet d’une application web **sécurisée, modulaire et extensible**.

---

## 👨‍💻 Auteur

**Zakaria Bouzouba**  
_Projet académique réalisé dans le cadre d’un apprentissage sur Spring MVC avec Thymeleaf._
