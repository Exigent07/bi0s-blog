"use client"

import Post from "@/components/Post";

export default function Home() {
  return (
    <>
      <main className="h-screen max-w-[1400px] flex flex-col gap-8 pt-[175px] px-4">
        <Post
        />
        <Post
          premise="Lorem ipsum dolor sit amet consectetur, adipisicing elit. Animi laudantium rem voluptas, adipisci ipsam hic sed! Odit, saepe officia rem dolores quaerat accusantium repellat aliquid doloribus temporibus error, vero, libero aspernatur mollitia possimus fugit fugiat voluptate delectus pariatur. Sapiente debitis magni repellat provident tenetur? Accusantium, earum dicta itaque dolor ut nesciunt nihil corporis non architecto nisi nostrum rem, iusto, exercitationem ullam eaque est odit magnam aperiam sit aliquid. Obcaecati fuga pariatur quaerat quia dolor est eligendi adipisci quis minus ipsam maxime, sequi odio quas. Error repellendus blanditiis cumque? Sapiente cupiditate voluptate dicta, quasi praesentium vitae ducimus eveniet excepturi est eligendi."
          meta={{
            author: ["Name1", "Name2"],
            date: ["yyyy-mm-dd", "yyyy-mm-dd"],
            category: ["Web", "Misc"],
            tags: "Test1",
          }}
        />
      </main>
    </>
  );
}
