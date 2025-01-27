"use client";

import { useState } from "react";
import ExtendedButton from "./ExtendedButton";
import SplitText from "@/utils/SplitText";
import Post from "./Post";

export default function SortPosts({ categoryTree, posts, sort, onNavigation }) {
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [selectedSubCategory, setSelectedSubCategory] = useState(null);

  const renderPosts = (postsToRender) => {
    return postsToRender.map((post, index) => (
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
    ));
  };

  const getSubCategories = (category) => {
    if (!categoryTree[category]) return {};
    return categoryTree[category].subcategories;
  };

  if (sort === 'tags' && selectedCategory) {
    return (
      <div className="w-full">
        <div className="mb-8 flex gap-4">
          <ExtendedButton
            onClick={() => setSelectedCategory(null)}
            className="!w-auto px-4"
          >
            ← Back to Tags
          </ExtendedButton>
        </div>
        <div className="grid grid-cols-1 gap-8">
          {renderPosts(categoryTree[selectedCategory].posts)}
        </div>
      </div>
    );
  }

  if (selectedSubCategory) {
    const subCategoryPosts = selectedCategory === null ? [] :
      getSubCategories(selectedCategory)[selectedSubCategory]?.posts || [];
    
    return (
      <div className="w-full">
        <div className="mb-8 flex gap-4">
          <ExtendedButton
            onClick={() => setSelectedSubCategory(null)}
            className="!w-auto px-4"
          >
            ← Back to {selectedCategory}
          </ExtendedButton>
        </div>
        <div className="grid grid-cols-1 gap-8">
          {renderPosts(subCategoryPosts)}
        </div>
      </div>
    );
  }

  if (selectedCategory && sort !== 'tags') {
    const subCategories = getSubCategories(selectedCategory);
    
    return (
      <div className="w-full">
        <div className="mb-8 flex gap-4">
          <ExtendedButton
            onClick={() => setSelectedCategory(null)}
            className="!w-auto px-4"
          >
            ← Back to Categories
          </ExtendedButton>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 sm:gap-8 md:gap-16 lg:gap-10">
          {Object.entries(subCategories).map(([key, value]) => (
            <ExtendedButton
              key={key}
              className="!w-[250px] !h-[100px] flex items-center justify-evenly"
              onClick={() => setSelectedSubCategory(key)}
            >
              <SplitText
                text={`${key} (${value.posts.length})`}
                className="text-xl font-highlight"
              />
            </ExtendedButton>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="items-center justify-center grid grid-cols-2 md:grid-cols-3 gap-4 sm:gap-8 md:gap-16 lg:gap-10">
      {Object.entries(categoryTree).map(([key, value]) => (
        <ExtendedButton
          className="!w-[250px] !h-[100px] flex items-center justify-evenly"
          onClick={() => setSelectedCategory(key)}
          key={key}
        >
          <SplitText
            text={`${key} (${value.posts.length})`}
            className="text-xl font-highlight"
          />
        </ExtendedButton>
      ))}
    </div>
  );
}