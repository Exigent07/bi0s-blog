import { readFile } from '@/lib/getPost';
import { notFound } from 'next/navigation';

export default function Post({ params }) {
    const { post } = params;
    const postPath = post.join('/');
    let postData;

    try {
        postData = readFile(postPath);
    } catch (error) {
        return (
            <>
              <p>Post not found: {postPath}</p>
            </>
        );
    }

    return (
        <main>
            <h1>{postData.title || 'Untitled'}</h1>
            <p>Author: {postData.author || 'Unknown'}</p>
            <p>Path: {postPath}</p>
        </main>
    );
}
