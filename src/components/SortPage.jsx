"use client";

import { useState } from 'react';
import SortPosts from '@/components/SortPosts';
import Link from 'next/link';

export default function SortPage({ sort, postsData }) {
  const getArchiveTree = () => {
    const archiveTree = {};
    postsData.posts.forEach(post => {
      const date = new Date(post.date);
      const year = date.getFullYear();
      const month = date.toLocaleString('default', { month: 'long' });
      
      if (!archiveTree[year]) {
        archiveTree[year] = {
          posts: [],
          subcategories: {}
        };
      }
      if (!archiveTree[year].subcategories[month]) {
        archiveTree[year].subcategories[month] = {
          posts: [],
          subcategories: {}
        };
      }
      
      archiveTree[year].posts.push(post);
      archiveTree[year].subcategories[month].posts.push(post);
    });
    return archiveTree;
  };

  const getTagTree = () => {
    const tagTree = {};
    postsData.posts.forEach(post => {
      post.tags.forEach(tag => {
        const cleanTag = tag.replace('#', '');
        if (!tagTree[cleanTag]) {
          tagTree[cleanTag] = {
            posts: [],
            subcategories: {}
          };
        }
        tagTree[cleanTag].posts.push(post);
      });
    });
    return tagTree;
  };

  const getTreeForSort = () => {
    switch (sort) {
      case 'categories':
        return postsData.categoryTree;
      case 'archives':
        return getArchiveTree();
      case 'tags':
        return getTagTree();
      default:
        return {};
    }
  };

  return (
    <SortPosts
      categoryTree={getTreeForSort()}
      posts={postsData.posts}
      sort={sort}
      onNavigation={() => {}}
    />
  );
}