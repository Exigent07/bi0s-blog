"use client";

import { useState, useEffect } from "react";
import Post from '@/components/Post';
import ExtendedButton from "./ExtendedButton";

export default function Pagination({ postsData }) {
  const [currentPage, setCurrentPage] = useState(1);
  const [searchQuery, setSearchQuery] = useState("");
  const postsPerPage = 7;
  
  const filteredPosts = searchQuery
    ? postsData.filter(post => 
        post.title?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        post.ctf?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        post.premise?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        post.category?.toLowerCase().includes(searchQuery.toLocaleLowerCase())
      )
    : postsData;
  
  const totalPages = Math.ceil(filteredPosts.length / postsPerPage);
  
  const indexOfLastPost = currentPage * postsPerPage;
  const indexOfFirstPost = indexOfLastPost - postsPerPage;
  const currentPosts = filteredPosts.slice(indexOfFirstPost, indexOfLastPost);
  
  const scrollToTop = () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToTop();
  }, [currentPage]);

  const handlePageChange = (pageNumber) => {
    setCurrentPage(pageNumber);
  };

  const handlePrevious = () => {
    if (currentPage > 1) {
      setCurrentPage(currentPage - 1);
    }
  };
  
  const handleNext = () => {
    if (currentPage < totalPages) {
      setCurrentPage(currentPage + 1);
    }
  };

  const generatePageNumbers = () => {
    const pages = [];
    if (totalPages <= 5) {
      for (let i = 1; i <= totalPages; i++) {
        pages.push(i);
      }
    } else {
      if (currentPage <= 3) {
        for (let i = 1; i <= 4; i++) {
          pages.push(i);
        }
        pages.push('...');
        pages.push(totalPages);
      } else if (currentPage >= totalPages - 2) {
        pages.push(1);
        pages.push('...');
        for (let i = totalPages - 3; i <= totalPages; i++) {
          pages.push(i);
        }
      } else {
        pages.push(1);
        pages.push('...');
        for (let i = currentPage - 1; i <= currentPage + 1; i++) {
          pages.push(i);
        }
        pages.push('...');
        pages.push(totalPages);
      }
    }
    return pages;
  };

  return (
    <>
      <main className="min-h-screen relative max-w-[1400px] flex flex-col gap-8 pt-[175px] px-4">
        {currentPosts.length > 0 ? (
            currentPosts.map((post, index) => (
                <Post
                    key={index}
                    title={post.title}
                    premise={post.premise}
                    meta={{
                      author: post.author,
                      date: post.date,
                      category: post.categories,
                      tags: post.tags,
                      path: post.path
                    }}
                />
            ))
        ) : (
            <p>No posts found</p>
        )}
        
        <div className="flex transition-colors duration-300 flex-col items-center gap-4 max-w-[1400px] py-12">
          <div className="flex gap-4 transition-colors duration-300">
            <ExtendedButton
              className="!w-[150px]"
              onClick={handlePrevious}
              disabled={currentPage === 1}
            >
              Previous
            </ExtendedButton>

              {generatePageNumbers().map((pageNumber, index) => (
                <ExtendedButton
                  key={index}
                  className={`${pageNumber === currentPage ? '' : ''} ${pageNumber === '...' ? 'cursor-default' : ''}`}
                  onClick={() => {
                      if (pageNumber !== '...') {
                          handlePageChange(pageNumber);
                      }
                  }}
                >
                  {pageNumber}
                </ExtendedButton>
              ))}

              <ExtendedButton
                className="!w-[150px]"
                onClick={handleNext}
                disabled={currentPage === totalPages}
              >
                Next
              </ExtendedButton>
          </div>
        </div>
      </main>
    </>
  );
}
