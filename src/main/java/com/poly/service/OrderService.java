package com.poly.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.poly.entity.Order;

import java.util.List;

public interface OrderService {
    Order create(JsonNode orderData);

    Order findById(Long id);

    List<Order> findByUsername(String username);
}
