#!/usr/bin/env python3
import asyncio
import logging
import sys
import time
from datetime import datetime

from colorama import Back, Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Initialize basic logging
from config.logging_config import configure_logging, get_logger


def print_soc_banner():
    """Display beautiful SOC security banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Fore.RED}███████{Fore.CYAN}╗ {Fore.RED}██████{Fore.CYAN}╗  {Fore.RED}██████{Fore.CYAN}╗    {Fore.YELLOW}███████{Fore.CYAN}╗{Fore.YELLOW}██████{Fore.CYAN}╗  {Fore.YELLOW}█████{Fore.CYAN}╗ {Fore.YELLOW}███{Fore.CYAN}╗   {Fore.YELLOW}███{Fore.CYAN}╗{Fore.YELLOW}███████{Fore.CYAN}╗  ║
║  {Fore.RED}██{Fore.CYAN}╔════╝{Fore.RED}██{Fore.CYAN}╔═══{Fore.RED}██{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}╔════╝    {Fore.YELLOW}██{Fore.CYAN}╔════╝{Fore.YELLOW}██{Fore.CYAN}╔══{Fore.YELLOW}██{Fore.CYAN}╗{Fore.YELLOW}██{Fore.CYAN}╔══{Fore.YELLOW}██{Fore.CYAN}╗{Fore.YELLOW}████{Fore.CYAN}╗ {Fore.YELLOW}████{Fore.CYAN}║{Fore.YELLOW}██{Fore.CYAN}╔════╝  ║
║  {Fore.RED}███████{Fore.CYAN}╗{Fore.RED}██{Fore.CYAN}║   {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║         {Fore.YELLOW}█████{Fore.CYAN}╗  {Fore.YELLOW}██████{Fore.CYAN}╔╝{Fore.YELLOW}███████{Fore.CYAN}║{Fore.YELLOW}██{Fore.CYAN}╔{Fore.YELLOW}████{Fore.CYAN}╔{Fore.YELLOW}██{Fore.CYAN}║{Fore.YELLOW}█████{Fore.CYAN}╗    ║
║  ╚════{Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║   {Fore.RED}██{Fore.CYAN}║{Fore.RED}██{Fore.CYAN}║         {Fore.YELLOW}██{Fore.CYAN}╔══╝  {Fore.YELLOW}██{Fore.CYAN}╔══{Fore.YELLOW}██{Fore.CYAN}╗{Fore.YELLOW}██{Fore.CYAN}╔══{Fore.YELLOW}██{Fore.CYAN}║{Fore.YELLOW}██{Fore.CYAN}║╚{Fore.YELLOW}██{Fore.CYAN}╔╝{Fore.YELLOW}██{Fore.CYAN}║{Fore.YELLOW}██{Fore.CYAN}╔══╝    ║
║  {Fore.RED}███████{Fore.CYAN}║╚{Fore.RED}██████{Fore.CYAN}╔╝╚{Fore.RED}██████{Fore.CYAN}╗    {Fore.YELLOW}██{Fore.CYAN}║     {Fore.YELLOW}██{Fore.CYAN}║  {Fore.YELLOW}██{Fore.CYAN}║{Fore.YELLOW}██{Fore.CYAN}║  {Fore.YELLOW}██{Fore.CYAN}║{Fore.YELLOW}██{Fore.CYAN}║ ╚═╝ {Fore.YELLOW}██{Fore.CYAN}║{Fore.YELLOW}███████{Fore.CYAN}╗  ║
║  ╚══════╝ ╚═════╝  ╚═════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝  ║
║                                                                              ║
║              {Fore.GREEN}🛡️  SECURITY OPERATIONS CENTER FRAMEWORK  🛡️{Fore.CYAN}               ║
║                                                                              ║
║  {Fore.MAGENTA}┌─────────────────────────────────────────────────────────────────────────┐{Fore.CYAN}  ║
║  {Fore.MAGENTA}│{Fore.WHITE} 🔍 THREAT DETECTION    🔄 AUTOMATED TRIAGE    📊 RISK ANALYSIS {Fore.MAGENTA}│{Fore.CYAN}  ║
║  {Fore.MAGENTA}│{Fore.WHITE} 🚨 INCIDENT RESPONSE   🤖 AI-POWERED AGENTS   📈 CORRELATION  {Fore.MAGENTA}│{Fore.CYAN}  ║
║  {Fore.MAGENTA}└─────────────────────────────────────────────────────────────────────────┘{Fore.CYAN}  ║
╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_security_status():
    """Display security system status"""
    print(f"\n{Fore.GREEN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print(f"┃                          {Fore.YELLOW}🔒 SECURITY STATUS OVERVIEW{Fore.GREEN}                          ┃")
    print(f"┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫")
    
    # Simulate loading status
    systems = [
        ("Threat Intelligence Engine", "ACTIVE", Fore.GREEN),
        ("Automated Triage System", "READY", Fore.GREEN),
        ("Correlation Engine", "ONLINE", Fore.GREEN),
        ("AI Analysis Agents", "INITIALIZED", Fore.GREEN),
        ("Security Orchestration", "STANDBY", Fore.YELLOW),
        ("Incident Response", "ARMED", Fore.GREEN)
    ]
    
    for system, status, color in systems:
        print(f"┃ {Fore.WHITE}{system:<30} [{color}{status:^10}{Fore.GREEN}] {Fore.CYAN}●{Fore.GREEN} ┃")
        time.sleep(0.1)
    
    print(f"┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")


def print_threat_landscape():
    """Display current threat landscape"""
    print(f"\n{Fore.RED}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print(f"┃                        {Fore.YELLOW}⚠️  CURRENT THREAT LANDSCAPE{Fore.RED}                         ┃")
    print(f"┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫")
    
    threats = [
        ("Advanced Persistent Threats", "MONITORED", "🎯", Fore.YELLOW),
        ("Ransomware Campaigns", "BLOCKED", "🛡️", Fore.GREEN),
        ("Phishing Attempts", "FILTERED", "📧", Fore.GREEN),
        ("Zero-Day Exploits", "SCANNING", "🔍", Fore.CYAN),
        ("Insider Threats", "ANALYZED", "👤", Fore.YELLOW),
        ("IoT Vulnerabilities", "PATCHED", "📱", Fore.GREEN)
    ]
    
    for threat, status, icon, color in threats:
        print(f"┃ {icon} {Fore.WHITE}{threat:<25} [{color}{status:^10}{Fore.RED}] {color}●{Fore.RED} ┃")
        time.sleep(0.1)
    
    print(f"┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")


def animated_loading(message="Initializing SOC Framework", duration=3):
    """Display animated loading sequence"""
    chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    end_time = time.time() + duration
    i = 0
    
    print(f"\n{Fore.CYAN}", end="")
    while time.time() < end_time:
        print(f"\r{chars[i % len(chars)]} {message}{'.' * ((i // 5) % 4):<3}", end="", flush=True)
        time.sleep(0.1)
        i += 1
    
    print(f"\r✅ {message} - Complete!{Style.RESET_ALL}")


def print_demo_header():
    """Print demo header"""
    print(f"\n{Back.BLUE}{Fore.WHITE}{'':=^80}{Style.RESET_ALL}")
    print(f"{Back.BLUE}{Fore.WHITE}{'  🚀 STARTING SOC FRAMEWORK DEMONSTRATION  ':^80}{Style.RESET_ALL}")
    print(f"{Back.BLUE}{Fore.WHITE}{'':=^80}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}🎯 Processing security alerts through AI-powered triage workflow...")
    print(f"{Fore.CYAN}📊 Analyzing threat patterns and generating response recommendations...")
    print(f"{Fore.CYAN}🔄 Correlating events across multiple security data sources...\n{Style.RESET_ALL}")


def print_beautiful_results(results, sample_alerts):
    """Print results with beautiful formatting"""
    print(f"\n{Fore.GREEN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
    print(f"┃                          {Fore.YELLOW}📊 SOC FRAMEWORK RESULTS{Fore.GREEN}                           ┃")
    print(f"┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫")
    print(f"┃ {Fore.WHITE}Processed: {Fore.CYAN}{len(results)}/{len(sample_alerts)} alerts successfully{Fore.GREEN}                              ┃")
    print(f"┃ {Fore.WHITE}Success Rate: {Fore.CYAN}{(len(results)/len(sample_alerts)*100):.1f}%{Fore.GREEN}                                              ┃")
    print(f"┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫")
    
    for i, result in enumerate(results, 1):
        status = result['triage_status']
        confidence = result['confidence_score']
        
        # Status icon and color
        if status == "critical":
            icon, color = "🚨", Fore.RED
        elif status == "triaged":
            icon, color = "⚠️", Fore.YELLOW
        elif status == "closed":
            icon, color = "✅", Fore.GREEN
        else:
            icon, color = "📋", Fore.CYAN
        
        # Confidence bar
        bar_length = int(confidence / 10)
        confidence_bar = "█" * bar_length + "░" * (10 - bar_length)
        
        print(f"┃ {icon} Alert {i:2}: {color}{status.upper():<10}{Fore.GREEN} │ Confidence: {color}{confidence:5.1f}%{Fore.GREEN} │{color}{confidence_bar}{Fore.GREEN}│ ┃")
    
    print(f"┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
    
    # Final security message
    print(f"\n{Fore.CYAN}┌─────────────────────────────────────────────────────────────────────────────┐")
    print(f"│ {Fore.GREEN}🛡️  Your network is being protected by advanced AI-powered security agents  🛡️{Fore.CYAN} │")
    print(f"│ {Fore.WHITE}   Continuous monitoring • Automated response • Intelligent threat hunting   {Fore.CYAN} │")
    print(f"└─────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")


# Set up logging with defaults
def setup_logging():
    """Set up basic logging for the application"""
    configure_logging()  # Use environment variables or defaults
    return get_logger("main")

def create_sample_alerts():
    """Create sample security alerts for testing"""
    return [
        {
            'timestamp': datetime.utcnow(),
            'source': 'firewall_logs',
            'event_type': 'suspicious_login',
            'severity': 'high',
            'source_ip': '192.168.1.100',
            'user': 'admin',
            'description': 'Multiple failed login attempts'
        },
        {
            'timestamp': datetime.utcnow(), 
            'source': 'endpoint_detection',
            'event_type': 'malware_detection',
            'severity': 'critical',
            'hostname': 'WORKSTATION-01',
            'description': 'Potential malware execution detected'
        }
    ]

async def process_alert(workflow, alert_data, alert_num):
    """Process a single alert through the workflow"""
    logger = get_logger("main")
    
    try:
        logger.info(f"Processing alert {alert_num}: {alert_data['event_type']}")
        
        # Create initial state
        from core.state_manager import SOCStateManager
        initial_state = SOCStateManager.create_initial_state(alert_data)
        
        # Run through workflow
        result_state = await workflow.ainvoke(initial_state)
        
        # Log results
        logger.info(
            f"Alert {alert_num} processed: {result_state['triage_status']} "
            f"(confidence: {result_state['confidence_score']:.1f}%)"
        )
        
        return result_state
        
    except Exception as e:
        logger.error(f"Error processing alert {alert_num}: {e}")
        return None

async def run_demo():
    """Run the SOC framework demo"""
    logger = get_logger("main")
    
    try:
        logger.info("Starting SOC Framework Demo")
        
        # Show demo header
        print_demo_header()
        
        # Initialize configuration
        from config.config_manager import init_config_manager
        config_manager = init_config_manager(enable_hot_reload=False)
        
        # Create workflow
        from core.workflow import create_soc_workflow
        workflow = create_soc_workflow()
        
        # Process sample alerts
        sample_alerts = create_sample_alerts()
        results = []
        
        for i, alert in enumerate(sample_alerts, 1):
            result = await process_alert(workflow, alert, i)
            if result:
                results.append(result)
            await asyncio.sleep(0.5)
        
        logger.info(f"Demo completed: processed {len(results)} alerts successfully")
        
        # Display beautiful results
        print_beautiful_results(results, sample_alerts)
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        print(f"{Fore.RED}❌ Demo failed: {e}{Style.RESET_ALL}")

def main():
    """Main entry point"""
    # Clear screen and show banner
    print("\033[2J\033[H")  # Clear screen
    print_soc_banner()
    
    try:
        # Animated loading
        animated_loading("Initializing SOC Framework", 2)
        
        # Set up logging
        logger = setup_logging()
        logger.info("Application started")
        
        animated_loading("Configuring Security Components", 1.5)
        print_security_status()
        
        animated_loading("Analyzing Threat Landscape", 1.5)
        print_threat_landscape()
        
        animated_loading("Preparing Demo Environment", 1)
        
        print(f"\n{Fore.GREEN}✅ SOC Framework initialization complete!{Style.RESET_ALL}")
        
        # Run the demo
        asyncio.run(run_demo())
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Demo interrupted by user{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to start application: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()