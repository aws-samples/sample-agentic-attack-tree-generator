"""
Performance tests for ThreatForest.

Tests performance characteristics, scalability, and resource usage
under various load conditions and project sizes.
"""

import pytest
import asyncio
import time
import psutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from threatforest.orchestrator import OrchestratorAgent
from threatforest.config import ThreatForestConfig

from tests.fixtures import (
    create_test_project,
    setup_mock_environment,
    create_performance_test_data,
    measure_performance,
    assert_performance_within_limits,
    cleanup_test_files
)


class TestPerformanceScaling:
    """Test performance scaling with different project sizes."""
    
    @pytest.fixture
    def performance_config(self):
        """Configuration optimized for performance testing."""
        return ThreatForestConfig(
            bedrock={
                "region": "us-east-1",
                "model": "anthropic.claude-3-haiku-20240307-v1:0",  # Faster model
                "timeout_seconds": 60
            },
            processing={
                "severity_threshold": "medium",
                "max_concurrent_agents": 4,
                "timeout_seconds": 120
            },
            output={
                "directory": "./perf-test-output",
                "format": "mermaid",
                "include_summary": True
            }
        )
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_small_project_performance(self, performance_config):
        """Test performance with small project (5 threats, 3 files)."""
        test_data = create_performance_test_data("small")
        project_path = create_test_project(
            "web_application",
            custom_files=test_data["additional_files"]
        )
        
        try:
            with setup_mock_environment(response_delay=0.01) as mock_env:
                # Set up files
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    test_data["readme_content"]
                )
                
                orchestrator = OrchestratorAgent(
                    config=performance_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                # Measure performance
                metrics = measure_performance(
                    orchestrator.execute_workflow,
                    str(project_path)
                )
                
                # Small project should complete quickly
                assert_performance_within_limits(
                    metrics,
                    max_execution_time=5.0,   # 5 seconds
                    max_memory_mb=50.0        # 50MB
                )
                
                # Validate results
                assert metrics["success"] is True
                results = metrics["result"]
                assert results["status"] == "completed"
                
                print(f"Small project performance: {metrics['execution_time']:.2f}s, "
                      f"{metrics['memory_usage']['peak_traced'] / 1024 / 1024:.1f}MB")
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_medium_project_performance(self, performance_config):
        """Test performance with medium project (20 threats, 10 files)."""
        test_data = create_performance_test_data("medium")
        project_path = create_test_project(
            "web_application",
            custom_files=test_data["additional_files"]
        )
        
        try:
            with setup_mock_environment(response_delay=0.02) as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    test_data["readme_content"]
                )
                
                orchestrator = OrchestratorAgent(
                    config=performance_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                metrics = measure_performance(
                    orchestrator.execute_workflow,
                    str(project_path)
                )
                
                # Medium project should complete within reasonable time
                assert_performance_within_limits(
                    metrics,
                    max_execution_time=15.0,  # 15 seconds
                    max_memory_mb=150.0       # 150MB
                )
                
                assert metrics["success"] is True
                
                print(f"Medium project performance: {metrics['execution_time']:.2f}s, "
                      f"{metrics['memory_usage']['peak_traced'] / 1024 / 1024:.1f}MB")
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.performance
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_large_project_performance(self, performance_config):
        """Test performance with large project (100 threats, 50 files)."""
        test_data = create_performance_test_data("large")
        project_path = create_test_project(
            "web_application",
            custom_files=test_data["additional_files"]
        )
        
        try:
            with setup_mock_environment(response_delay=0.05) as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    test_data["readme_content"]
                )
                
                orchestrator = OrchestratorAgent(
                    config=performance_config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                metrics = measure_performance(
                    orchestrator.execute_workflow,
                    str(project_path)
                )
                
                # Large project may take longer but should still be reasonable
                assert_performance_within_limits(
                    metrics,
                    max_execution_time=60.0,  # 1 minute
                    max_memory_mb=500.0       # 500MB
                )
                
                assert metrics["success"] is True
                
                print(f"Large project performance: {metrics['execution_time']:.2f}s, "
                      f"{metrics['memory_usage']['peak_traced'] / 1024 / 1024:.1f}MB")
        
        finally:
            cleanup_test_files(project_path)


class TestConcurrencyPerformance:
    """Test performance under concurrent load."""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_analysis_performance(self):
        """Test performance with multiple concurrent analyses."""
        config = ThreatForestConfig(
            processing={"max_concurrent_agents": 2}
        )
        
        # Create multiple test projects
        projects = []
        for i in range(3):
            project = create_test_project("web_application")
            projects.append(project)
        
        try:
            with setup_mock_environment(response_delay=0.1) as mock_env:
                # Set up all projects
                for project in projects:
                    mock_env["file_system"].create_file(
                        f"{project}/README.md",
                        (project / "README.md").read_text()
                    )
                
                # Create orchestrators
                orchestrators = [
                    OrchestratorAgent(
                        config=config,
                        bedrock_client=mock_env["bedrock_client"],
                        agents=mock_env["agents"]
                    )
                    for _ in projects
                ]
                
                # Measure concurrent execution
                start_time = time.time()
                
                tasks = [
                    orchestrator.execute_workflow(str(project))
                    for orchestrator, project in zip(orchestrators, projects)
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                end_time = time.time()
                total_time = end_time - start_time
                
                # All should succeed
                for result in results:
                    assert not isinstance(result, Exception)
                    assert result["status"] == "completed"
                
                # Concurrent execution should be faster than sequential
                # (with mock delays, should be roughly the same as single execution)
                assert total_time < 5.0  # Should complete within 5 seconds
                
                print(f"Concurrent analysis of {len(projects)} projects: {total_time:.2f}s")
        
        finally:
            for project in projects:
                cleanup_test_files(project)
    
    @pytest.mark.performance
    def test_thread_safety(self):
        """Test thread safety of core components."""
        config = ThreatForestConfig()
        
        def create_and_run_orchestrator(project_id):
            """Create and run orchestrator in thread."""
            project_path = create_test_project("web_application")
            
            try:
                with setup_mock_environment() as mock_env:
                    mock_env["file_system"].create_file(
                        f"{project_path}/README.md",
                        (project_path / "README.md").read_text()
                    )
                    
                    orchestrator = OrchestratorAgent(
                        config=config,
                        bedrock_client=mock_env["bedrock_client"],
                        agents=mock_env["agents"]
                    )
                    
                    # Run synchronously in thread
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    try:
                        result = loop.run_until_complete(
                            orchestrator.execute_workflow(str(project_path))
                        )
                        return project_id, result, None
                    except Exception as e:
                        return project_id, None, e
                    finally:
                        loop.close()
            
            finally:
                cleanup_test_files(project_path)
        
        # Run multiple threads
        num_threads = 3
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [
                executor.submit(create_and_run_orchestrator, i)
                for i in range(num_threads)
            ]
            
            results = []
            for future in as_completed(futures):
                project_id, result, error = future.result()
                results.append((project_id, result, error))
        
        # All threads should complete successfully
        for project_id, result, error in results:
            assert error is None, f"Thread {project_id} failed: {error}"
            assert result is not None
            assert result["status"] == "completed"
        
        print(f"Thread safety test completed with {num_threads} threads")


class TestMemoryUsage:
    """Test memory usage patterns and potential leaks."""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_memory_usage_scaling(self):
        """Test memory usage scaling with project size."""
        config = ThreatForestConfig()
        memory_results = {}
        
        # Test different project sizes
        sizes = ["small", "medium"]  # Skip large for CI performance
        
        for size in sizes:
            test_data = create_performance_test_data(size)
            project_path = create_test_project(
                "web_application",
                custom_files=test_data["additional_files"]
            )
            
            try:
                with setup_mock_environment() as mock_env:
                    mock_env["file_system"].create_file(
                        f"{project_path}/README.md",
                        test_data["readme_content"]
                    )
                    
                    orchestrator = OrchestratorAgent(
                        config=config,
                        bedrock_client=mock_env["bedrock_client"],
                        agents=mock_env["agents"]
                    )
                    
                    metrics = measure_performance(
                        orchestrator.execute_workflow,
                        str(project_path)
                    )
                    
                    memory_results[size] = {
                        "peak_mb": metrics["memory_usage"]["peak_traced"] / 1024 / 1024,
                        "final_rss_mb": metrics["memory_usage"]["final_rss"] / 1024 / 1024,
                        "threat_count": test_data["expected_metrics"]["threat_count"]
                    }
                    
                    assert metrics["success"] is True
            
            finally:
                cleanup_test_files(project_path)
        
        # Memory usage should scale reasonably with project size
        if "small" in memory_results and "medium" in memory_results:
            small_memory = memory_results["small"]["peak_mb"]
            medium_memory = memory_results["medium"]["peak_mb"]
            
            # Medium project should use more memory but not excessively
            memory_ratio = medium_memory / small_memory if small_memory > 0 else 1
            assert memory_ratio < 10, f"Memory usage scaling too high: {memory_ratio}x"
            
            print(f"Memory scaling - Small: {small_memory:.1f}MB, Medium: {medium_memory:.1f}MB")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_memory_leak_detection(self):
        """Test for potential memory leaks in repeated executions."""
        config = ThreatForestConfig()
        
        try:
            import psutil
            initial_memory = psutil.Process().memory_info().rss
            psutil_available = True
        except ImportError:
            pytest.skip("psutil not available for memory leak detection")
            
        memory_samples = []
        
        # Run multiple iterations
        for i in range(5):
            project_path = create_test_project("web_application")
            
            try:
                with setup_mock_environment() as mock_env:
                    mock_env["file_system"].create_file(
                        f"{project_path}/README.md",
                        (project_path / "README.md").read_text()
                    )
                    
                    orchestrator = OrchestratorAgent(
                        config=config,
                        bedrock_client=mock_env["bedrock_client"],
                        agents=mock_env["agents"]
                    )
                    
                    await orchestrator.execute_workflow(str(project_path))
                    
                    # Sample memory after each iteration
                    if psutil_available:
                        current_memory = psutil.Process().memory_info().rss
                        memory_samples.append(current_memory)
            
            finally:
                cleanup_test_files(project_path)
        
        # Check for significant memory growth
        if len(memory_samples) >= 3:
            first_sample = memory_samples[0]
            last_sample = memory_samples[-1]
            
            memory_growth = (last_sample - first_sample) / first_sample
            
            # Allow for some growth but not excessive (< 50%)
            assert memory_growth < 0.5, f"Potential memory leak detected: {memory_growth:.1%} growth"
            
            print(f"Memory leak test - Growth: {memory_growth:.1%}")


class TestAPIPerformance:
    """Test performance characteristics of API calls."""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_bedrock_api_performance(self):
        """Test Bedrock API call performance and retry behavior."""
        with setup_mock_environment(response_delay=0.1) as mock_env:
            bedrock_client = mock_env["bedrock_client"]
            
            # Test single API call performance
            start_time = time.time()
            
            response = await bedrock_client.invoke_model(
                "anthropic.claude-3-sonnet-20240229-v1:0",
                {"prompt": "Extract information from this text"}
            )
            
            end_time = time.time()
            call_duration = end_time - start_time
            
            assert response is not None
            assert call_duration < 1.0  # Should complete within 1 second (including mock delay)
            
            print(f"Single API call duration: {call_duration:.3f}s")
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_concurrent_api_calls(self):
        """Test performance of concurrent API calls."""
        with setup_mock_environment(response_delay=0.1) as mock_env:
            bedrock_client = mock_env["bedrock_client"]
            
            # Test concurrent API calls
            num_calls = 5
            
            async def make_api_call(call_id):
                return await bedrock_client.invoke_model(
                    "anthropic.claude-3-sonnet-20240229-v1:0",
                    {"prompt": f"Test call {call_id}"}
                )
            
            start_time = time.time()
            
            tasks = [make_api_call(i) for i in range(num_calls)]
            responses = await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_duration = end_time - start_time
            
            # All calls should succeed
            assert len(responses) == num_calls
            for response in responses:
                assert response is not None
            
            # Concurrent calls should be faster than sequential
            # With 0.1s delay each, concurrent should be ~0.1s, sequential would be ~0.5s
            assert total_duration < 0.3  # Allow some overhead
            
            print(f"Concurrent API calls ({num_calls}): {total_duration:.3f}s")


class TestResourceLimits:
    """Test behavior under resource constraints."""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test handling of operation timeouts."""
        config = ThreatForestConfig(
            processing={"timeout_seconds": 1}  # Very short timeout
        )
        
        project_path = create_test_project("web_application")
        
        try:
            # Use longer delays to trigger timeout
            with setup_mock_environment(response_delay=2.0) as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                # Should handle timeout gracefully
                result = await orchestrator.execute_workflow(str(project_path))
                
                # May complete with timeout errors or fail gracefully
                assert result["status"] in ["failed", "completed_with_errors"]
                
                if result["status"] == "failed":
                    assert "timeout" in str(result.get("error", "")).lower()
        
        finally:
            cleanup_test_files(project_path)
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_high_concurrency_limits(self):
        """Test behavior with high concurrency settings."""
        config = ThreatForestConfig(
            processing={"max_concurrent_agents": 10}  # High concurrency
        )
        
        project_path = create_test_project("web_application")
        
        try:
            with setup_mock_environment() as mock_env:
                mock_env["file_system"].create_file(
                    f"{project_path}/README.md",
                    (project_path / "README.md").read_text()
                )
                
                orchestrator = OrchestratorAgent(
                    config=config,
                    bedrock_client=mock_env["bedrock_client"],
                    agents=mock_env["agents"]
                )
                
                metrics = measure_performance(
                    orchestrator.execute_workflow,
                    str(project_path)
                )
                
                # Should complete successfully even with high concurrency
                assert metrics["success"] is True
                
                # Performance should still be reasonable
                assert metrics["execution_time"] < 10.0
        
        finally:
            cleanup_test_files(project_path)