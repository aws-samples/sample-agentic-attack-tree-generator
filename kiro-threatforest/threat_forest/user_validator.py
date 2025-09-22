"""
User validation system for extracted information.
"""

import json
from typing import Dict, Any, List, Optional
from pathlib import Path

from .models import ApplicationInfo
from .utils import get_logger


class UserValidator:
    """Handles user validation and correction of extracted information."""
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def validate_application_info(self, app_info: ApplicationInfo) -> ApplicationInfo:
        """
        Present application info to user for validation and correction.
        
        Args:
            app_info: Extracted application information
            
        Returns:
            Validated and potentially corrected ApplicationInfo
        """
        self.logger.info("Presenting extracted information for user validation")
        
        print("\n" + "="*60)
        print("EXTRACTED APPLICATION INFORMATION")
        print("="*60)
        
        self._display_application_info(app_info)
        
        print("\n" + "-"*60)
        print("Please review the extracted information above.")
        
        while True:
            response = input("\nIs this information correct? (y/n/edit): ").strip().lower()
            
            if response in ['y', 'yes']:
                self.logger.info("User approved extracted information")
                return app_info
            elif response in ['n', 'no']:
                print("Please provide the correct information:")
                return self._collect_corrected_info(app_info)
            elif response in ['e', 'edit']:
                return self._interactive_edit(app_info)
            else:
                print("Please enter 'y' for yes, 'n' for no, or 'edit' to modify specific fields.")
    
    def _display_application_info(self, app_info: ApplicationInfo) -> None:
        """Display application information in a readable format."""
        print(f"\nApplication Name: {app_info.name}")
        print(f"Description: {app_info.description}")
        
        if app_info.technologies:
            print(f"Technologies: {', '.join(app_info.technologies)}")
        else:
            print("Technologies: None specified")
        
        if app_info.programming_languages:
            print(f"Programming Languages: {', '.join(app_info.programming_languages)}")
        else:
            print("Programming Languages: None specified")
        
        print(f"Sector: {app_info.sector or 'Not specified'}")
        
        if app_info.security_objectives:
            print(f"Security Objectives: {', '.join(app_info.security_objectives)}")
        else:
            print("Security Objectives: Not specified")
        
        if app_info.additional_context:
            print("\nAdditional Context:")
            for key, value in app_info.additional_context.items():
                if key != 'source_files':  # Skip internal metadata
                    print(f"  {key}: {value}")
    
    def _collect_corrected_info(self, app_info: ApplicationInfo) -> ApplicationInfo:
        """Collect corrected information from user."""
        print("\nPlease provide the correct information (press Enter to keep current value):")
        
        # Application name
        name = input(f"Application Name [{app_info.name}]: ").strip()
        if name:
            app_info.name = name
        
        # Description
        description = input(f"Description [{app_info.description[:50]}...]: ").strip()
        if description:
            app_info.description = description
        
        # Technologies
        current_tech = ', '.join(app_info.technologies) if app_info.technologies else ''
        tech_input = input(f"Technologies (comma-separated) [{current_tech}]: ").strip()
        if tech_input:
            app_info.technologies = [t.strip() for t in tech_input.split(',') if t.strip()]
        
        # Programming languages
        current_langs = ', '.join(app_info.programming_languages) if app_info.programming_languages else ''
        lang_input = input(f"Programming Languages (comma-separated) [{current_langs}]: ").strip()
        if lang_input:
            app_info.programming_languages = [l.strip() for l in lang_input.split(',') if l.strip()]
        
        # Sector
        sector = input(f"Sector [{app_info.sector}]: ").strip()
        if sector:
            app_info.sector = sector
        
        # Security objectives
        current_objectives = ', '.join(app_info.security_objectives) if app_info.security_objectives else ''
        obj_input = input(f"Security Objectives (comma-separated) [{current_objectives}]: ").strip()
        if obj_input:
            app_info.security_objectives = [o.strip() for o in obj_input.split(',') if o.strip()]
        
        self.logger.info("User provided corrected information")
        return app_info
    
    def _interactive_edit(self, app_info: ApplicationInfo) -> ApplicationInfo:
        """Interactive editing of specific fields."""
        fields = {
            '1': ('name', 'Application Name'),
            '2': ('description', 'Description'),
            '3': ('technologies', 'Technologies'),
            '4': ('programming_languages', 'Programming Languages'),
            '5': ('sector', 'Sector'),
            '6': ('security_objectives', 'Security Objectives')
        }
        
        while True:
            print("\nWhich field would you like to edit?")
            for key, (field, display_name) in fields.items():
                current_value = getattr(app_info, field)
                if isinstance(current_value, list):
                    display_value = ', '.join(current_value) if current_value else 'None'
                else:
                    display_value = current_value or 'None'
                
                # Truncate long values
                if len(str(display_value)) > 50:
                    display_value = str(display_value)[:50] + '...'
                
                print(f"{key}. {display_name}: {display_value}")
            
            print("0. Done editing")
            
            choice = input("\nEnter your choice (0-6): ").strip()
            
            if choice == '0':
                break
            elif choice in fields:
                field_name, display_name = fields[choice]
                self._edit_field(app_info, field_name, display_name)
            else:
                print("Invalid choice. Please enter a number between 0 and 6.")
        
        return app_info
    
    def _edit_field(self, app_info: ApplicationInfo, field_name: str, display_name: str) -> None:
        """Edit a specific field."""
        current_value = getattr(app_info, field_name)
        
        if isinstance(current_value, list):
            current_display = ', '.join(current_value) if current_value else ''
            new_value = input(f"\n{display_name} (comma-separated) [{current_display}]: ").strip()
            if new_value:
                setattr(app_info, field_name, [v.strip() for v in new_value.split(',') if v.strip()])
        else:
            new_value = input(f"\n{display_name} [{current_value}]: ").strip()
            if new_value:
                setattr(app_info, field_name, new_value)
        
        print(f"Updated {display_name}")
    
    def skip_validation(self, app_info: ApplicationInfo) -> ApplicationInfo:
        """Skip user validation (for automated mode)."""
        self.logger.info("Skipping user validation (automated mode)")
        return app_info