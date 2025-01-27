import { readFile } from '@/lib/getPost';
import { notFound } from 'next/navigation';

export default async function Post({ params }) {
  const { sort, post } = await params;
  const sortTypes = ["categories", "archives", "tags", "posts"];
  const postPath = post.join('/') + ".md";
  let postData;

  if (!sortTypes.includes(sort)) {
    notFound();
  }

  try {
    postData = readFile(postPath);
  } catch (error) {
    notFound();
  }

  return (
    <main>
      <h1>{postData.title || 'Untitled'}</h1>
      <p>Author: {postData.author || 'Unknown'}</p>
      <p>Path: {postPath}</p>
    </main>
  );
}
