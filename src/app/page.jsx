import Pagination from "@/components/Pagination";
import { getPostsData } from "@/lib/getPost";

export default function Home() {
  const { posts, categoryTree } = getPostsData();

  return (
    <>
      <Pagination postsData={posts} categoryTree={categoryTree} />
    </>
  );
}