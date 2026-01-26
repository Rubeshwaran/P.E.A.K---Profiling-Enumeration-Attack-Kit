import os
import datetime
import markdown # You may need to: pip install markdown

class ReportGenerator:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_filename(self, target_name, ext="md"):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        clean_target = "".join(c for c in target_name if c.isalnum() or c in ('-','_'))
        return f"{self.output_dir}/PEAK_REPORT_{clean_target}_{timestamp}.{ext}"

    def save_report(self, content, target="Generic_Target"):
        # 1. Save as Markdown (Editable)
        md_filename = self.generate_filename(target, "md")
        with open(md_filename, "w", encoding="utf-8") as f:
            f.write(content)
            
        # 2. (Optional) Convert to HTML for easy viewing
        html_filename = self.generate_filename(target, "html")
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: sans-serif; max-width: 800px; margin: auto; padding: 20px; line-height: 1.6; }}
                h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
                code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
                pre {{ background: #282c34; color: #abb2bf; padding: 15px; overflow-x: auto; border-radius: 5px; }}
                .alert {{ background: #fff3cd; color: #856404; padding: 10px; border-radius: 5px; }}
            </style>
        </head>
        <body>
            {markdown.markdown(content, extensions=['fenced_code', 'tables'])}
        </body>
        </html>
        """
        with open(html_filename, "w", encoding="utf-8") as f:
            f.write(html_content)

        return os.path.abspath(html_filename)

# Usage Example:
# generator = ReportGenerator()
# path = generator.save_report("# Scan Results\n...", "example.com")
# print(f"Report saved to: {path}")