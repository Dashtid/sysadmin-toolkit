#!/usr/bin/env python3
"""
Example Python script demonstrating best practices for the sysadmin-toolkit.

This script shows proper structure, type hints, error handling, and logging
patterns that should be followed for all Python scripts in this project.

Usage:
    uv run python example-python-script.py --name "System" --count 3
    uv run python example-python-script.py --help

Examples:
    # Run with default values
    uv run python example-python-script.py

    # Run with custom parameters
    uv run python example-python-script.py --name "Server" --count 5 --verbose

    # Demonstrate error handling
    uv run python example-python-script.py --name "" --count -1

Requirements:
    - Python 3.9+
    - uv package manager
    - No external dependencies (uses stdlib only)

Author: David Dashti
Version: 1.0.0
Last Updated: 2025-10-18
"""

from typing import Optional, List
import argparse
import logging
import sys
from pathlib import Path


# Configure logging with ASCII markers (no emojis)
def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Configure logging for the script.

    Args:
        verbose: Enable verbose (DEBUG) logging

    Returns:
        Configured logger instance
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='[%(levelname)s] %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)


logger = setup_logging()


class SystemHealthChecker:
    """
    Example class demonstrating proper Python structure.

    This class shows how to implement type hints, docstrings,
    and error handling in a professional manner.
    """

    def __init__(self, system_name: str, check_count: int = 3) -> None:
        """
        Initialize the health checker.

        Args:
            system_name: Name of the system to check
            check_count: Number of health checks to perform

        Raises:
            ValueError: If system_name is empty or check_count is invalid
        """
        if not system_name or not system_name.strip():
            raise ValueError("system_name cannot be empty")

        if check_count < 1:
            raise ValueError("check_count must be at least 1")

        self.system_name = system_name
        self.check_count = check_count
        self.checks_performed = 0
        self.issues_found: List[str] = []

        logger.debug(
            f"Initialized SystemHealthChecker for '{system_name}' "
            f"with {check_count} checks"
        )

    def run_health_check(self) -> bool:
        """
        Run health checks on the system.

        Returns:
            True if all checks passed, False otherwise
        """
        logger.info(f"[i] Starting health check for: {self.system_name}")

        try:
            for i in range(self.check_count):
                check_num = i + 1
                logger.debug(f"Running check {check_num}/{self.check_count}")

                # Simulate health check (in real script, this would check actual system health)
                check_passed = self._perform_check(check_num)

                if check_passed:
                    logger.info(f"[+] Check {check_num}/{self.check_count}: PASS")
                else:
                    logger.warning(f"[!] Check {check_num}/{self.check_count}: FAIL")
                    self.issues_found.append(f"Check {check_num} failed")

                self.checks_performed += 1

            # Report results
            if not self.issues_found:
                logger.info(f"[+] All {self.checks_performed} checks passed successfully")
                return True
            else:
                logger.error(
                    f"[-] {len(self.issues_found)} issue(s) found in "
                    f"{self.checks_performed} checks"
                )
                for issue in self.issues_found:
                    logger.error(f"    - {issue}")
                return False

        except Exception as e:
            logger.error(f"[-] Health check failed with error: {e}")
            raise

    def _perform_check(self, check_number: int) -> bool:
        """
        Perform a single health check.

        Args:
            check_number: The check number being performed

        Returns:
            True if check passed, False otherwise
        """
        # Simulate check logic (in real script, implement actual checks)
        # For demo purposes, fail every 3rd check
        return check_number % 3 != 0

    def get_report(self) -> str:
        """
        Generate a summary report of health checks.

        Returns:
            Formatted report string
        """
        report_lines = [
            f"\n{'=' * 60}",
            f"Health Check Report: {self.system_name}",
            f"{'=' * 60}",
            f"Total checks performed: {self.checks_performed}",
            f"Issues found: {len(self.issues_found)}",
        ]

        if self.issues_found:
            report_lines.append("\nIssues:")
            for i, issue in enumerate(self.issues_found, 1):
                report_lines.append(f"  {i}. {issue}")
        else:
            report_lines.append("\n[+] No issues found - system healthy")

        report_lines.append("=" * 60)
        return "\n".join(report_lines)


def validate_arguments(args: argparse.Namespace) -> None:
    """
    Validate command-line arguments.

    Args:
        args: Parsed command-line arguments

    Raises:
        ValueError: If arguments are invalid
    """
    if not args.name or not args.name.strip():
        raise ValueError("--name cannot be empty")

    if args.count < 1 or args.count > 100:
        raise ValueError("--count must be between 1 and 100")

    logger.debug(f"Arguments validated: name={args.name}, count={args.count}")


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Example Python script for sysadmin-toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --name "WebServer" --count 5
  %(prog)s --name "Database" --count 10 --verbose

For more information, see CONTRIBUTING.md
        """
    )

    parser.add_argument(
        '--name',
        type=str,
        default='System',
        help='Name of the system to check (default: System)'
    )

    parser.add_argument(
        '--count',
        type=int,
        default=3,
        help='Number of health checks to perform (default: 3, max: 100)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose (DEBUG) logging'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )

    return parser.parse_args()


def main() -> int:
    """
    Main entry point for the script.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    try:
        # Parse and validate arguments
        args = parse_arguments()

        # Set up logging based on verbosity
        global logger
        logger = setup_logging(args.verbose)

        logger.debug(f"Script started with arguments: {args}")

        # Validate arguments
        validate_arguments(args)

        # Create health checker instance
        checker = SystemHealthChecker(
            system_name=args.name,
            check_count=args.count
        )

        # Run health checks
        all_passed = checker.run_health_check()

        # Display report
        print(checker.get_report())

        # Return appropriate exit code
        if all_passed:
            logger.info("[+] Script completed successfully")
            return 0
        else:
            logger.warning("[!] Script completed with warnings")
            return 1

    except ValueError as e:
        logger.error(f"[-] Invalid input: {e}")
        logger.info("[i] Use --help for usage information")
        return 1

    except KeyboardInterrupt:
        logger.warning("\n[!] Script interrupted by user")
        return 130

    except Exception as e:
        logger.error(f"[-] Unexpected error: {e}", exc_info=True)
        logger.info("[!] This is likely a bug - please report it on GitHub")
        return 1


if __name__ == "__main__":
    sys.exit(main())
