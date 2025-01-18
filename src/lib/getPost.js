import matter from "gray-matter";
import fs from "fs";
import path from "path";
import { marked } from "marked";

const BASE_DIR = path.resolve(process.cwd(), "posts");

function getCategory(filePath) {
    const relativePath = path.relative(BASE_DIR, path.dirname(filePath));
    
    if (relativePath === '') {
        return [];
    }

    return relativePath.split(path.sep).filter(Boolean);
}

function readFile(filePath) {
    const fullPath = path.resolve(BASE_DIR, filePath);
    if (!fullPath.startsWith(BASE_DIR)) {
        throw new Error("Access to files outside the allowed directory is not permitted.");
    }

    const file = fs.readFileSync(fullPath, { encoding: "utf-8" });
    const { data, content } = matter(file);

    const dirCategories = getCategory(fullPath);

    const metadata = {
        title: data.title?.trim() || '',
        date: data.date 
            ? new Date(data.date).toLocaleDateString('en-US', { day: '2-digit', month: 'long', year: 'numeric' }) 
            : new Date().toLocaleDateString('en-US', { day: '2-digit', month: 'long', year: 'numeric' }),
        updated: data.updated ? new Date(data.updated) : new Date(),
        categories: [
            ...dirCategories,
            ...(Array.isArray(data.categories) ? data.categories : [data.categories]).filter(Boolean)
        ],
        tags: Array.isArray(data.tags) ? data.tags.map(tag => `#${tag.trim()}`) : [data.tags].filter(Boolean),
        author: data.author?.trim() || '',
        author_url: data.author_url?.trim() || '',
        premise: '',
        content: '',
        directory: {
            full: dirCategories.join('/'),
            hierarchy: dirCategories,
            depth: dirCategories.length
        }
    };

    const tldrMatch = content.match(/(?:\*\*|)tl;dr(?:\*\*|)[\r\n\- ]*([\s\S]*?)<!--\s*more\s*-->/i);
    if (tldrMatch) {
        const rawPremise = tldrMatch[1].trim();
        const htmlPremise = marked.parse(rawPremise);
        metadata.premise = htmlPremise.replace(/\n/g, '');
    }

    const restContent = content.split('<!--more-->')[1] || '';
    const htmlContent = marked.parse(restContent.trim());
    metadata.content = htmlContent.replace(/\n/g, '');

    const assetFolder = path.join(path.dirname(fullPath), path.basename(filePath, '.md'));
    const hasAssetFolder = fs.existsSync(assetFolder);

    const urlPath = `posts/${dirCategories.join('/')}${path.basename(filePath, '.md')}`;

    return {
        ...metadata,
        path: urlPath,
        full_source: fullPath,
        asset_dir: hasAssetFolder ? assetFolder : null,
        filename: path.basename(filePath, '.md'),
        raw: content
    };
}

function getAllFiles(dir) {
    let results = [];
    const items = fs.readdirSync(dir);

    for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
            results = results.concat(getAllFiles(fullPath));
        } else if (item.endsWith('.md')) {
            results.push(path.relative(BASE_DIR, fullPath));
        }
    }

    return results;
}

function getPostsData() {
    if (!fs.existsSync(BASE_DIR)) {
        return [];
    }

    const filePaths = getAllFiles(BASE_DIR);

    const posts = filePaths.map(filePath => {
        try {
            return readFile(filePath);
        } catch (error) {
            console.error(`Error processing ${filePath}:`, error);
            return null;
        }
    })
    .filter(Boolean)
    .sort((a, b) => b.date - a.date);

    posts.forEach((post, index) => {
        post.prev = index > 0 ? posts[index - 1] : null;
        post.next = index < posts.length - 1 ? posts[index + 1] : null;
    });

    const categoryTree = {};
    posts.forEach(post => {
        let currentLevel = categoryTree;
        post.directory.hierarchy.forEach(category => {
            if (!currentLevel[category]) {
                currentLevel[category] = {
                    posts: [],
                    subcategories: {}
                };
            }
            currentLevel[category].posts.push(post);
            currentLevel = currentLevel[category].subcategories;
        });
    });

    return {
        posts,
        categoryTree
    };
}

console.log(getPostsData());

export {
    getPostsData,
    readFile
};