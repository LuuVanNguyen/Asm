package com.poly.dao;

import com.poly.entity.Authority;
import com.poly.entity.Customers;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface AuthorityDAO extends JpaRepository<Authority, Integer> {
    @Query("SELECT DISTINCT a FROM Authority a WHERE a.customer IN ?1")
    List<Authority> authoritiesOf(List<Customers> customers);
}
