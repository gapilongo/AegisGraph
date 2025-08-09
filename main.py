#!/usr/bin/env python3
import asyncio
import logging
from datetime import datetime

from config.config_manager import init_config_manager
from core.state_manager import SOCStateManager
from core.workflow import create_soc_workflow

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
    try:
        logger.info(f"🔄 Processing alert {alert_num}: {alert_data['event_type']}")
        
        # Create initial state
        initial_state = SOCStateManager.create_initial_state(alert_data)
        
        # Run through workflow
        result_state = await workflow.ainvoke(initial_state)
        
        # Log results
        logger.info(f"   Alert {alert_num} processed:")
        logger.info(f"   Status: {result_state['triage_status']}")
        logger.info(f"   Confidence: {result_state['confidence_score']:.1f}%")
        
        return result_state
        
    except Exception as e:
        logger.error(f"  Error processing alert {alert_num}: {e}")
        return None

async def run_demo():
    """Run the SOC framework demo"""
    logger.info("   Starting SOC Framework Demo")
    
    try:
        # Initialize configuration
        config_manager = init_config_manager(enable_hot_reload=False)
        
        # Create workflow
        workflow = create_soc_workflow()
        
        # Process sample alerts
        sample_alerts = create_sample_alerts()
        
        results = []
        for i, alert in enumerate(sample_alerts, 1):
            result = await process_alert(workflow, alert, i)
            if result:
                results.append(result)
            await asyncio.sleep(0.5)
        
        logger.info(f"   Processed {len(results)} alerts successfully!")
        
    except Exception as e:
        logger.error(f"   Demo failed: {e}")

def main():
    print("=" * 60)
    print("SOC TRIAGE & ORCHESTRATION FRAMEWORK")
    print("=" * 60)
    asyncio.run(run_demo())

if __name__ == "__main__":
    main()