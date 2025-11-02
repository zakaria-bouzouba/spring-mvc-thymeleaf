package net.zakaria.springmvcthymeleaf.repository;

import net.zakaria.springmvcthymeleaf.entities.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long> {
}
