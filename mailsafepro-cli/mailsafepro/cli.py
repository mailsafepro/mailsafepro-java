"""
MailSafePro CLI

Command-line interface for email validation.
"""

import click
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import track
from .client import MailSafeProClient
from .config import Config

console = Console()

@click.group()
@click.version_option(version="1.0.0")
@click.option(
    '--api-key',
    envvar='MAILSAFEPRO_API_KEY',
    help='API key (or set MAILSAFEPRO_API_KEY env var)'
)
@click.option(
    '--base-url',
    default='https://api.mailsafepro.com',
    help='API base URL'
)
@click.pass_context
def cli(ctx, api_key, base_url):
    """
    MailSafePro CLI - Email validation from your terminal.
    
    Examples:
    
      # Validate single email
      mailsafepro validate user@example.com
      
      # Batch validate from file
      mailsafepro batch emails.txt -o results.json
      
      # Check usage
      mailsafepro usage
    """
    ctx.ensure_object(dict)
    try:
        ctx.obj['client'] = MailSafeProClient(api_key=api_key, base_url=base_url)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        console.print("\n[yellow]Tip:[/yellow] Set your API key:")
        console.print("  export MAILSAFEPRO_API_KEY='your-key-here'")
        console.print("  or use: mailsafepro --api-key KEY validate email@example.com")
        sys.exit(1)

@cli.command()
@click.argument('email')
@click.option('--smtp/--no-smtp', default=False, help='Check SMTP mailbox')
@click.option('--json', 'output_json', is_flag=True, help='Output as JSON')
@click.pass_context
def validate(ctx, email, smtp, output_json):
    """
    Validate a single email address.
    
    Example:
        mailsafepro validate user@example.com --smtp
    """
    client = ctx.obj['client']
    
    try:
        with console.status(f"[bold green]Validating {email}..."):
            result = client.validate(email, check_smtp=smtp)
        
        if output_json:
            import json
            console.print_json(json.dumps(result, indent=2))
        else:
            # Pretty table output
            table = Table(title=f"Validation: {email}")
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("Valid", "✅ Yes" if result.get('valid') else "❌ No")
            table.add_row("Risk Score", f"{result.get('risk_score', 0):.2f}")
            table.add_row("Disposable", "Yes" if result.get('is_disposable') else "No")
            
            provider = result.get('provider', {})
            table.add_row("Provider", provider.get('name', 'Unknown'))
            
            if result.get('deliverability'):
                table.add_row("Deliverability", result['deliverability'].get('status', 'unknown'))
            
            console.print(table)
            
            # Summary message
            if result.get('valid'):
                console.print("\n✅ [green]Email is valid[/green]")
            else:
                console.print("\n❌ [red]Email is invalid[/red]")
                if result.get('detail'):
                    console.print(f"   Reason: {result['detail']}")
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.argument('file', type=click.File('r'))
@click.option('--output', '-o', type=click.File('w'), help='Output file (JSON)')
@click.option('--smtp/--no-smtp', default=False, help='Check SMTP')
@click.pass_context
def batch(ctx, file, output, smtp):
    """
    Validate emails from a file (one per line).
    
    Example:
        mailsafepro batch emails.txt -o results.json
    """
    client = ctx.obj['client']
    
    # Read emails
    emails = [line.strip() for line in file if line.strip()]
    
    if not emails:
        console.print("[red]Error:[/red] No emails found in file")
        sys.exit(1)
    
    console.print(f"[cyan]Found {len(emails)} emails to validate[/cyan]")
    
    try:
        with console.status(f"[bold green]Validating {len(emails)} emails..."):
            results = client.batch_validate(emails, check_smtp=smtp)
        
        # Write results
        if output:
            import json
            json.dump(results, output, indent=2)
            console.print(f"\n✅ Results written to {output.name}")
        else:
            # Print summary
            valid_count = results.get('valid_count', 0)
            invalid_count = results.get('invalid_count', 0)
            
            console.print(f"\n[green]✅ Valid:[/green] {valid_count}/{len(emails)}")
            console.print(f"[red]❌ Invalid:[/red] {invalid_count}/{len(emails)}")
            console.print(f"[cyan]⏱️  Time:[/cyan] {results.get('processing_time', 0):.2f}s")
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.pass_context
def usage(ctx):
    """
    Check API usage and quota.
    
    Example:
        mailsafepro usage
    """
    client = ctx.obj['client']
    
    try:
        with console.status("[bold green]Fetching usage..."):
            quota = client.get_usage()
        
        table = Table(title="Usage Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="yellow")
        
        table.add_row("Plan", quota.get('plan', 'Unknown'))
        table.add_row("Used", str(quota.get('used', 0)))
        table.add_row("Limit", str(quota.get('limit', 0)))
        table.add_row("Remaining", str(quota.get('remaining', 0)))
        
        # Usage percentage
        used = quota.get('used', 0)
        limit = quota.get('limit', 1)
        percentage = (used / limit * 100) if limit > 0 else 0
        table.add_row("Usage %", f"{percentage:.1f}%")
        
        console.print(table)
        
        # Warning if high usage
        if percentage > 80:
            console.print("\n[yellow]⚠️  Warning: You've used over 80% of your quota[/yellow]")
    
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

@cli.command()
@click.argument('api_key')
def configure(api_key):
    """
    Save API key to config file.
    
    Example:
        mailsafepro configure YOUR_API_KEY
    """
    try:
        config = Config()
        config.save_api_key(api_key)
        console.print("✅ [green]API key saved successfully[/green]")
        console.print(f"   Location: ~/.mailsafepro/config")
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)

if __name__ == '__main__':
    cli(obj={})
