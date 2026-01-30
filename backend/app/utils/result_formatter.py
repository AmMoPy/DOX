import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class ResultFormatter:
    """
    Format search results with minimal overhead
    Compatible with both AI chat and search endpoints
    """
    
    def __init__(self):
        # Regex to detect section patterns
        self.section_pattern = re.compile(
            r'^(\d+(?:\.\d+)*)\.\s+([A-Z][A-Z\s]+?)(?:\s+\(continued\))?(?:\n|$)',
            re.MULTILINE
        )
    

    def format_search_results(
        self,
        raw_results: Dict[str, Any],
        max_results: int,
        max_preview_chars: int = 300
    ) -> Dict[str, Any]:
        """
        Format /query/search results
        
        Input: current response format
        Output: Enhanced format with structure + similarity scores
        """
        if not raw_results.get("documents") or not raw_results["documents"][0]:
            return raw_results
        
        documents = raw_results["documents"][0][:max_results]
        metadatas = raw_results["metadatas"][0][:max_results]
        distances = raw_results["distances"][0][:max_results]
        
        formatted_results = []
        
        for idx, doc in enumerate(documents):
            # Parse section info from chunk text
            section_info = self._parse_section(doc)
            
            # Convert distance to similarity (0.0-1.0 scale, higher = better)
            distance = distances[idx] if idx < len(distances) else 1.0
            similarity = max(0.0, 1.0 - distance)  # Clamp to [0, 1]
            
            # Get metadata safely
            meta = metadatas[idx] if idx < len(metadatas) else {}
            
            formatted_results.append({
                "id": idx + 1,
                "section": {
                    "number": section_info["number"],
                    "title": section_info["title"],
                    "level": section_info["level"],
                    "is_continuation": section_info["is_continuation"]
                },
                "preview": self._create_preview(doc, max_preview_chars),
                "full_content": doc,
                "relevance": {
                    "similarity_score": round(similarity, 4),
                    "percentage": f"{similarity * 100:.1f}%",
                    "distance": round(distance, 4)  # for debugging
                },
                "metadata": {
                    "document_id": meta.get("document_id"),
                    "filename": meta.get("filename"),
                    "title": meta.get("title"),
                    "category": meta.get("category")
                }
            })
        
        # Sort by similarity (highest first)
        formatted_results.sort(
            key=lambda x: x["relevance"]["similarity_score"],
            reverse=True
        )
    
        return formatted_results

    
    def format_ai_sources(
        self,
        contexts: List[str],
        metadatas: List[Dict],
        distances: List[float],
        max_sources: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Format sources for AI chat responses
        
        Returns simplified source list with structure
        """
        sources = []
        
        for idx, (context, meta, dist) in enumerate(zip(contexts, metadatas, distances)):
            if idx >= max_sources:
                break
            
            section_info = self._parse_section(context)
            similarity = max(0.0, 1.0 - dist)
            
            sources.append({
                "rank": idx + 1,
                "section": section_info["title"],
                "section_number": section_info["number"],
                "filename": meta.get("filename", "Unknown"),
                "relevance": f"{similarity * 100:.0f}%",
                "preview": context[:150] + "..." if len(context) > 150 else context
            })
        
        return sources
    

    def _parse_section(self, text: str) -> Dict[str, Any]:
        """
        Extract section metadata from chunk text
        Handles both old and new chunker formats
        """
        if not text:
            return {
                "number": None,
                "title": "Content",
                "level": 0,
                "is_continuation": False
            }
        
        # Try to match section header
        match = self.section_pattern.search(text)
        
        if match:
            section_num = match.group(1)
            title = match.group(2).strip()
            is_continuation = "(continued)" in text[:200]
            
            # Calculate hierarchy level
            level = section_num.count('.') + 1
            
            return {
                "number": section_num,
                "title": title,
                "level": level,
                "is_continuation": is_continuation
            }
        
        # Fallback: Use first line as title
        first_line = text.split('\n')[0].strip()
        
        return {
            "number": None,
            "title": first_line[:100] if first_line else "Content",
            "level": 0,
            "is_continuation": False
        }
    
    
    def _create_preview(self, text: str, max_chars: int) -> str:
        """
        Create smart preview that preserves structure
        """
        lines = text.split('\n')
        
        # First line (usually section header)
        header = lines[0] if lines else ""
        
        # Content lines (skip empty)
        content_lines = [l.strip() for l in lines[1:] if l.strip()]
        
        if not content_lines:
            return header
        
        # Build preview
        preview = header
        remaining = max_chars - len(header)
        
        if remaining > 50:
            content = ' '.join(content_lines)
            if len(content) <= remaining:
                preview += "\n\n" + content
            else:
                preview += "\n\n" + content[:remaining - 3] + "..."
        
        return preview


# Global instance
formatter = ResultFormatter()