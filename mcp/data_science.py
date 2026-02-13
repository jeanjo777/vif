"""
MCP Data Science - Data analysis, visualization, and machine learning
"""
from .base import MCPServer, MCPTool
from typing import Dict, Any, List
import json
import base64
import io
from pathlib import Path


class DataScienceMCP(MCPServer):
    """Data Science MCP Server - CSV analysis, charts, ML predictions, SQL generation"""

    def __init__(self):
        super().__init__(
            name="data_science",
            description="Data analysis, visualization, machine learning, and SQL query generation"
        )
        self.workspace = Path("/tmp/vif_datascience")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._init_tools()

    def _init_tools(self):
        """Initialize all data science tools"""

        # Tool 1: Analyze CSV
        self.register_tool(MCPTool(
            name="analyze_csv",
            description="Analyze CSV file: statistics, insights, visualizations",
            parameters={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to CSV file"
                    },
                    "file_url": {
                        "type": "string",
                        "description": "URL to CSV file"
                    },
                    "analysis_type": {
                        "type": "string",
                        "description": "Type: basic, detailed, statistical, correlation",
                        "enum": ["basic", "detailed", "statistical", "correlation", "all"],
                        "default": "detailed"
                    },
                    "columns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific columns to analyze"
                    }
                }
            },
            handler=self._analyze_csv
        ))

        # Tool 2: Create chart
        self.register_tool(MCPTool(
            name="create_chart",
            description="Create visualization from data: line, bar, pie, scatter, histogram",
            parameters={
                "type": "object",
                "properties": {
                    "chart_type": {
                        "type": "string",
                        "description": "Chart type",
                        "enum": ["line", "bar", "pie", "scatter", "histogram", "box", "heatmap"],
                        "default": "line"
                    },
                    "data": {
                        "type": "object",
                        "description": "Chart data: {x: [], y: []} or {labels: [], values: []}"
                    },
                    "file_path": {
                        "type": "string",
                        "description": "Path to data file (CSV/JSON)"
                    },
                    "x_column": {
                        "type": "string",
                        "description": "X-axis column name"
                    },
                    "y_column": {
                        "type": "string",
                        "description": "Y-axis column name"
                    },
                    "title": {
                        "type": "string",
                        "description": "Chart title"
                    },
                    "save_path": {
                        "type": "string",
                        "description": "Path to save chart image"
                    }
                },
                "required": ["chart_type"]
            },
            handler=self._create_chart
        ))

        # Tool 3: ML prediction
        self.register_tool(MCPTool(
            name="ml_predict",
            description="Machine learning: regression, classification, clustering",
            parameters={
                "type": "object",
                "properties": {
                    "task": {
                        "type": "string",
                        "description": "ML task type",
                        "enum": ["regression", "classification", "clustering", "forecast"],
                        "default": "regression"
                    },
                    "data_path": {
                        "type": "string",
                        "description": "Path to training data (CSV)"
                    },
                    "target_column": {
                        "type": "string",
                        "description": "Target/label column name"
                    },
                    "features": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Feature column names"
                    },
                    "test_data": {
                        "type": "object",
                        "description": "New data to predict on"
                    },
                    "model_type": {
                        "type": "string",
                        "description": "Model: linear, decision_tree, random_forest, xgboost, auto",
                        "default": "auto"
                    }
                },
                "required": ["task"]
            },
            handler=self._ml_predict
        ))

        # Tool 4: SQL query builder
        self.register_tool(MCPTool(
            name="sql_query_builder",
            description="Generate SQL query from natural language description",
            parameters={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of query"
                    },
                    "table_schema": {
                        "type": "object",
                        "description": "Database schema: {table_name: [column_names]}"
                    },
                    "database_type": {
                        "type": "string",
                        "description": "Database type: postgresql, mysql, sqlite, mssql",
                        "enum": ["postgresql", "mysql", "sqlite", "mssql", "generic"],
                        "default": "postgresql"
                    },
                    "validate": {
                        "type": "boolean",
                        "description": "Validate SQL syntax",
                        "default": True
                    }
                },
                "required": ["description"]
            },
            handler=self._sql_query_builder
        ))

    def _analyze_csv(self, file_path: str = None, file_url: str = None,
                    analysis_type: str = "detailed", columns: List[str] = None) -> Dict[str, Any]:
        """Analyze CSV file"""
        try:
            import pandas as pd
            import numpy as np

            # Load CSV
            if file_url:
                df = pd.read_csv(file_url)
            elif file_path:
                df = pd.read_csv(file_path)
            else:
                return {"error": "No file path or URL provided"}

            # Filter columns if specified
            if columns:
                df = df[columns]

            analysis = {
                "shape": {"rows": len(df), "columns": len(df.columns)},
                "columns": list(df.columns)
            }

            if analysis_type in ["basic", "detailed", "all"]:
                analysis["basic_stats"] = {
                    "dtypes": df.dtypes.astype(str).to_dict(),
                    "missing_values": df.isnull().sum().to_dict(),
                    "unique_counts": df.nunique().to_dict()
                }

            if analysis_type in ["detailed", "statistical", "all"]:
                # Numeric columns statistics
                numeric_cols = df.select_dtypes(include=[np.number]).columns
                if len(numeric_cols) > 0:
                    stats_df = df[numeric_cols].describe()
                    analysis["statistics"] = stats_df.to_dict()

            if analysis_type in ["correlation", "all"]:
                # Correlation matrix
                numeric_cols = df.select_dtypes(include=[np.number]).columns
                if len(numeric_cols) > 1:
                    corr_matrix = df[numeric_cols].corr()
                    analysis["correlation"] = corr_matrix.to_dict()

            if analysis_type in ["detailed", "all"]:
                # Sample data
                analysis["sample_data"] = df.head(5).to_dict(orient="records")

                # Categorical analysis
                categorical_cols = df.select_dtypes(include=['object']).columns
                if len(categorical_cols) > 0:
                    analysis["categorical_summary"] = {}
                    for col in categorical_cols[:5]:  # Limit to 5 columns
                        value_counts = df[col].value_counts().head(10)
                        analysis["categorical_summary"][col] = value_counts.to_dict()

            return analysis

        except Exception as e:
            return {"error": str(e)}

    def _create_chart(self, chart_type: str, data: Dict = None, file_path: str = None,
                     x_column: str = None, y_column: str = None, title: str = None,
                     save_path: str = None) -> Dict[str, Any]:
        """Create chart/visualization"""
        try:
            import pandas as pd
            import matplotlib.pyplot as plt
            import numpy as np

            # Load data
            if file_path:
                if file_path.endswith('.csv'):
                    df = pd.read_csv(file_path)
                elif file_path.endswith('.json'):
                    df = pd.read_json(file_path)
                else:
                    return {"error": "Unsupported file format"}

                if x_column and y_column:
                    x_data = df[x_column].values
                    y_data = df[y_column].values
                else:
                    return {"error": "x_column and y_column required for file data"}

            elif data:
                if 'x' in data and 'y' in data:
                    x_data = data['x']
                    y_data = data['y']
                elif 'labels' in data and 'values' in data:
                    x_data = data['labels']
                    y_data = data['values']
                else:
                    return {"error": "Invalid data format"}
            else:
                return {"error": "No data provided"}

            # Create chart
            fig, ax = plt.subplots(figsize=(10, 6))

            if chart_type == "line":
                ax.plot(x_data, y_data, marker='o')
            elif chart_type == "bar":
                ax.bar(x_data, y_data)
            elif chart_type == "pie":
                ax.pie(y_data, labels=x_data, autopct='%1.1f%%')
            elif chart_type == "scatter":
                ax.scatter(x_data, y_data)
            elif chart_type == "histogram":
                ax.hist(y_data, bins=30, edgecolor='black')
            elif chart_type == "box":
                ax.boxplot(y_data)
            elif chart_type == "heatmap":
                import matplotlib.pyplot as plt
                plt.imshow(y_data, cmap='viridis', aspect='auto')
                plt.colorbar()
            else:
                return {"error": f"Unknown chart type: {chart_type}"}

            if title:
                ax.set_title(title)
            ax.set_xlabel(x_column or "X")
            ax.set_ylabel(y_column or "Y")

            # Save chart
            if not save_path:
                save_path = str(self.workspace / f"chart_{chart_type}.png")

            plt.tight_layout()
            plt.savefig(save_path, dpi=100, bbox_inches='tight')
            plt.close()

            # Encode image to base64
            with open(save_path, 'rb') as f:
                image_b64 = base64.b64encode(f.read()).decode('utf-8')

            return {
                "chart_type": chart_type,
                "save_path": save_path,
                "image_base64": image_b64,
                "success": True
            }

        except Exception as e:
            return {"error": str(e)}

    def _ml_predict(self, task: str, data_path: str = None, target_column: str = None,
                   features: List[str] = None, test_data: Dict = None,
                   model_type: str = "auto") -> Dict[str, Any]:
        """Machine learning prediction"""
        try:
            import pandas as pd
            import numpy as np
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import mean_squared_error, accuracy_score, r2_score

            # Load training data
            if not data_path:
                return {"error": "data_path required for training"}

            df = pd.read_csv(data_path)

            if not target_column or target_column not in df.columns:
                return {"error": f"Invalid target column: {target_column}"}

            # Prepare features and target
            if features:
                X = df[features]
            else:
                X = df.drop(columns=[target_column])

            y = df[target_column]

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            # Select model
            if task == "regression":
                if model_type == "auto" or model_type == "linear":
                    from sklearn.linear_model import LinearRegression
                    model = LinearRegression()
                elif model_type == "decision_tree":
                    from sklearn.tree import DecisionTreeRegressor
                    model = DecisionTreeRegressor()
                elif model_type == "random_forest":
                    from sklearn.ensemble import RandomForestRegressor
                    model = RandomForestRegressor()
                else:
                    return {"error": f"Unknown model type: {model_type}"}

            elif task == "classification":
                if model_type == "auto":
                    from sklearn.ensemble import RandomForestClassifier
                    model = RandomForestClassifier()
                elif model_type == "decision_tree":
                    from sklearn.tree import DecisionTreeClassifier
                    model = DecisionTreeClassifier()
                elif model_type == "random_forest":
                    from sklearn.ensemble import RandomForestClassifier
                    model = RandomForestClassifier()
                else:
                    return {"error": f"Unknown model type: {model_type}"}

            elif task == "clustering":
                from sklearn.cluster import KMeans
                model = KMeans(n_clusters=3)
                # Clustering doesn't need train/test split
                model.fit(X)
                predictions = model.predict(X)
                return {
                    "task": task,
                    "model_type": "kmeans",
                    "n_clusters": 3,
                    "predictions": predictions.tolist()[:10],
                    "cluster_centers": model.cluster_centers_.tolist()
                }

            else:
                return {"error": f"Unknown task: {task}"}

            # Train model
            model.fit(X_train, y_train)

            # Evaluate
            y_pred = model.predict(X_test)

            if task == "regression":
                metrics = {
                    "rmse": float(np.sqrt(mean_squared_error(y_test, y_pred))),
                    "r2_score": float(r2_score(y_test, y_pred))
                }
            else:  # classification
                metrics = {
                    "accuracy": float(accuracy_score(y_test, y_pred))
                }

            # Predict on new data if provided
            new_predictions = None
            if test_data:
                test_df = pd.DataFrame([test_data])
                if features:
                    test_df = test_df[features]
                new_predictions = model.predict(test_df).tolist()

            return {
                "task": task,
                "model_type": model_type,
                "metrics": metrics,
                "feature_importance": getattr(model, 'feature_importances_', None),
                "predictions": new_predictions,
                "success": True
            }

        except Exception as e:
            return {"error": str(e)}

    def _sql_query_builder(self, description: str, table_schema: Dict = None,
                          database_type: str = "postgresql",
                          validate: bool = True) -> Dict[str, Any]:
        """Generate SQL query from natural language"""
        try:
            import os
            import requests

            # Use OpenRouter to generate SQL
            url = "https://openrouter.ai/api/v1/chat/completions"

            headers = {
                "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY')}",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://vif.lat"
            }

            # Build prompt
            schema_text = ""
            if table_schema:
                schema_text = "\n\nDatabase Schema:\n"
                for table, columns in table_schema.items():
                    schema_text += f"Table: {table}\n"
                    schema_text += f"Columns: {', '.join(columns)}\n\n"

            prompt = f"""Generate a {database_type} SQL query for the following request:

{description}
{schema_text}
Provide ONLY the SQL query without explanation. Use proper {database_type} syntax."""

            data = {
                "model": "anthropic/claude-3.5-sonnet",
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 1000
            }

            response = requests.post(url, headers=headers, json=data, timeout=30)
            response.raise_for_status()
            result = response.json()

            sql_query = result['choices'][0]['message']['content']

            # Extract SQL from markdown if present
            if "```sql" in sql_query:
                sql_query = sql_query.split("```sql")[1].split("```")[0].strip()
            elif "```" in sql_query:
                sql_query = sql_query.split("```")[1].split("```")[0].strip()

            # Basic validation
            validation_errors = []
            if validate:
                sql_upper = sql_query.upper()
                dangerous_keywords = ["DROP", "DELETE", "TRUNCATE", "ALTER"]
                for keyword in dangerous_keywords:
                    if keyword in sql_upper:
                        validation_errors.append(f"Warning: Query contains {keyword} statement")

            return {
                "description": description,
                "sql_query": sql_query,
                "database_type": database_type,
                "validation_errors": validation_errors,
                "success": True
            }

        except Exception as e:
            return {"error": str(e)}
