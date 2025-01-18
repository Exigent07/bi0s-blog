import ExtendedButton from "./ExtendedButton";
import Outline from "./Outline";
import Read from "../svg/read.svg";
import { GoPersonFill } from "react-icons/go";
import { MdDateRange } from "react-icons/md";
import { BiCategory } from "react-icons/bi";
import { FaHashtag } from "react-icons/fa";
import SplitText from "@/utils/SplitText";
import parse from 'html-react-parser';

export default function Post({
  title = "No Title",
  premise = "Lorem ipsum dolor sit amet consectetur adipisicing elit. Eaque sint, ipsam rem quaerat enim mollitia in ipsa error dolores consectetur iure et illo nobis fugit ratione, optio suscipit maxime. Maiores.",
  meta = {
    author: "Author Name",
    category: "Category",
    date: "yyyy-mm-dd",
    tags: ["#hashtag1", "#hashtag2", "#hashtag3", "#hashtag4", "#hashtag1", "#hashtag2", "#hashtag3", "#hashtag4"],
  },
  className = "",
  articleClass = "",
}) {
  const metaItems = [
    { icon: <GoPersonFill />, value: meta.author, multiple: "Authors" },
    { icon: <MdDateRange />, value: meta.date, multiple: "Dates" },
    { icon: <BiCategory />, value: meta.category, multiple: "Categories" },
    { icon: <FaHashtag />, value: meta.tags, multiple: "Tags" },
  ];

  return (
    <Outline outlineColor="bg-border">
      <div className={`post-wrapper w-full h-full ${className}`}>
        <article
          className={`w-full relative h-full flex items-stretch justify-center p-0.5 ${articleClass}`}
        >
          <section className="post-content flex flex-col gap-4 p-8 pb-4 w-[1145px] bg-subtle">
            <h2 className="text-4xl font-heading">{title}</h2>
            <div className="text-lg font-body mb-3">{parse(premise)}</div>
            <ExtendedButton className="!w-[200px] flex items-center justify-evenly">
              <div className="split-container">
                <SplitText
                  text="Read More"
                  className="text-xl font-highlight"
                />
              </div>
              <Read className="h-[32px] w-[32px] text-muted" />
            </ExtendedButton>
          </section>

          <section className="post-metadata flex flex-col gap-2 p-4 w-[200px] bg-shadow text-muted text-sm">
            {metaItems.map((item, index) => (
              <div key={index} className="metadata-item">
                <div className="flex items-center gap-2">
                  {item.icon}
                  <span className="font-meta">
                    {Array.isArray(item.value) ? item.multiple : item.value}
                  </span>
                </div>
                {Array.isArray(item.value) && (
                  <div className={`${item.multiple.toLowerCase()} mt-1`}>
                    {item.value.map((key, idx) => (
                      <span
                        key={idx}
                        className="inline-block text-xs font-highlight py-1 px-1"
                      >
                        {key}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </section>
        </article>
      </div>
    </Outline>
  );
}
