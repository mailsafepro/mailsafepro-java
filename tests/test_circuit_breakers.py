"""
Tests for circuit breaker management.
"""

import pytest
from app.resilience.circuit_breakers import CircuitBreakerManager
import pybreaker

def test_get_breaker_creates_instance():
    """Test that get_breaker creates a new instance."""
    breaker = CircuitBreakerManager.get_breaker("test_service")
    assert breaker is not None
    assert isinstance(breaker, pybreaker.CircuitBreaker)

def test_get_breaker_returns_singleton():
    """Test that get_breaker returns same instance."""
    breaker1 = CircuitBreakerManager.get_breaker("smtp")
    breaker2 = CircuitBreakerManager.get_breaker("smtp")
    assert breaker1 is breaker2

def test_circuit_breaker_opens_after_failures():
    """Test that circuit opens after max failures."""
    breaker = CircuitBreakerManager.get_breaker("test_failures")
    
    # Trigger failures (default fail_max=5)
    for i in range(6):
        try:
            @breaker
            def failing_function():
                raise Exception("Simulated failure")
            failing_function()
        except:
            pass
    
    # Circuit should be open
    assert str(breaker.current_state) == "open"

def test_get_breaker_stats():
    """Test getting breaker statistics."""
    breaker = CircuitBreakerManager.get_breaker("stats_test")
    stats = CircuitBreakerManager.get_breaker_stats("stats_test")
    
    assert stats is not None
    assert "state" in stats
    assert "failure_count" in stats
    assert "name" in stats

def test_reset_breaker():
    """Test manual breaker reset."""
    breaker = CircuitBreakerManager.get_breaker("reset_test")
    
    # Trigger failures to open circuit
    for _ in range(6):
        try:
            @breaker
            def fail():
                raise Exception("Fail")
            fail()
        except:
            pass
    
    assert str(breaker.current_state) == "open"
    
    # Reset
    success = CircuitBreakerManager.reset_breaker("reset_test")
    assert success is True
    assert str(breaker.current_state) == "closed"

def test_get_all_breakers():
    """Test getting all breakers."""
    CircuitBreakerManager.get_breaker("smtp")
    CircuitBreakerManager.get_breaker("dns")
    
    all_breakers = CircuitBreakerManager.get_all_breakers()
    assert len(all_breakers) >= 2
    assert "smtp" in all_breakers
    assert "dns" in all_breakers
