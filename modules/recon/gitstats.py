#!/usr/bin/env python3
"""
GitStats - Analyseur de dépôt Git
Author: Ludovic Mouly
"""

import git
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import json


class GitStats:
    def __init__(self, repo_path="."):
        try:
            self.repo = git.Repo(repo_path)
        except git.InvalidGitRepositoryError:
            raise ValueError("Pas un dépôt Git valide!")
    
    def get_commit_stats(self, days=30):
        """Statistiques des commits"""
        since = datetime.now() - timedelta(days=days)
        commits = list(self.repo.iter_commits('HEAD', since=since))
        
        stats = {
            'total_commits': len(commits),
            'authors': Counter(),
            'files_changed': Counter(),
            'additions': defaultdict(int),
            'deletions': defaultdict(int),
            'commits_by_day': defaultdict(int),
            'commits_by_hour': defaultdict(int)
        }
        
        for commit in commits:
            author = commit.author.name
            stats['authors'][author] += 1
            
            commit_date = datetime.fromtimestamp(commit.committed_date)
            stats['commits_by_day'][commit_date.strftime('%Y-%m-%d')] += 1
            stats['commits_by_hour'][commit_date.hour] += 1
            
            try:
                if commit.parents:
                    diff = commit.parents[0].diff(commit)
                    for change in diff:
                        if change.a_path:
                            stats['files_changed'][change.a_path] += 1
                    
                    stats['additions'][author] += commit.stats.total['insertions']
                    stats['deletions'][author] += commit.stats.total['deletions']
            except:
                pass
        
        return stats
    
    def get_repo_info(self):
        """Informations générales du dépôt"""
        branches = [b.name for b in self.repo.branches]
        tags = [t.name for t in self.repo.tags]
        
        try:
            remote_url = next(self.repo.remote().urls, 'N/A')
        except:
            remote_url = 'N/A'
        
        info = {
            'current_branch': self.repo.active_branch.name,
            'total_branches': len(branches),
            'total_tags': len(tags),
            'remote_url': remote_url
        }
        
        return info


# Fonction pour l'API
def analyze_git_repo(data):
    """Analyse un dépôt Git et retourne les stats"""
    try:
        repo_path = data.get('repo_path', '.')
        days = data.get('days', 30)
        
        analyzer = GitStats(repo_path)
        repo_info = analyzer.get_repo_info()
        commit_stats = analyzer.get_commit_stats(days)
        
        # Conversion des Counter et defaultdict en dict
        return {
            'repo_info': repo_info,
            'total_commits': commit_stats['total_commits'],
            'top_authors': dict(commit_stats['authors'].most_common(10)),
            'top_files': dict(commit_stats['files_changed'].most_common(10)),
            'additions_by_author': dict(commit_stats['additions']),
            'deletions_by_author': dict(commit_stats['deletions']),
            'commits_by_hour': dict(commit_stats['commits_by_hour']),
            'commits_by_day': dict(sorted(commit_stats['commits_by_day'].items()))
        }
    
    except ValueError as e:
        return {'error': str(e)}
    except Exception as e:
        return {'error': f'Erreur lors de l\'analyse: {str(e)}'}