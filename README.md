# IT SECURITY AGENT

## Environment Variables

Create a `.env` file from the provided template:

```bash
cp .env.sample .env
```

Then fill in the required configuration values before running the project. 

## Task

- Use the vulnerability data to build an agent that scans for vulnerabilities in your Project:
  - NVD (National Vulnerability Database) Data Feeds
- Goal: Your security agent uses pictures of software or SBOMs to identify vulnerabilities
- Build the agent responsible, analyze your data etc.
- Show your results in a documented juypter-notebook as a presentation

---

## Environment Setup & Data Initialize

Before running the notebook, enter into the root directory of the project, start the MongoDB service with Docker Compose:

```
docker compose up -d
```

Place the downloaded NVD JSON files in the following directory:

```
<project_root>/data/nvdcve/
```

The directory should contain files such as:

```
<project_root>/data/nvdcve/nvdcve-2.0-2002.json
<project_root>/data/nvdcve/nvdcve-2.0-2003.json
...
<project_root>/data/nvdcve/nvdcve-2.0-2026.json
```

Then initialize the MongoDB database by running:

```bash
uv run python scripts/init_db_data.py
```

The script parses the NVD JSON files, extracts the fields required for vulnerability analysis, and stores the processed CVE records in MongoDB. After this step, the notebook can be executed for exploratory data analysis and vulnerability matching.

## Project Notebooks

The project documentation is organized into several Jupyter notebooks. `main.ipynb` serves as the primary report, containing the complete project description, methodology, system architecture, implementation details, evaluation, and conclusions. The remaining notebooks provide supporting analyses and documentation for specific aspects of the project:

| Notebook           | Description                                                                                                          |
|--------------------|----------------------------------------------------------------------------------------------------------------------|
| `main.ipynb`       | Main project report containing the complete workflow and documentation.                                              |
| `eda.ipynb`        | Exploratory Data Analysis (EDA) of the NVD vulnerability dataset.                                                    |
| `code.ipynb`       | Core implementation, testing, and execution of the IT Security Agent.                                                |
| `xai.ipynb`        | Explainable AI (XAI) analysis using SHAP to interpret the auxiliary prediction model.                                |
| `model_card.ipynb` | Model Card describing the system's intended use, limitations, ethical considerations, and Responsible AI assessment. |
