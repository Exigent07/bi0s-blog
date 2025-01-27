import SortPosts from "@/components/SortPosts";
import { notFound } from "next/navigation";
import { getPostsData } from "@/lib/getPost";
import SortPage from "@/components/SortPage";

export default async function Sort({ params }) {
  const { sort } = await params;
  const { posts, categoryTree } = getPostsData();
  const sortTypes = ["categories", "archives", "tags", "posts"];

  if (!sortTypes.includes(sort)) {
    notFound();
  }

  return (
    <main>
        <SortPage
            postsData={{
                posts: posts,
                categoryTree: categoryTree
            }}
            sort={sort}
        />
    </main>
  );
}

