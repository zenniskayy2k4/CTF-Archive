"use client";
import Link from "next/link";
import { useState } from "react";

export default function Home() {
  const [showError, setShowError] = useState(false);
  return (
    <div className="items-center justify-items-center min-h-screen sm:p-20 font-[family-name:var(--font-geist-sans)]">
      <h1 className="text-4xl font-bold">WELCOME TO THE EPIC CAKE BATTLES OF HISTORY!!!</h1>
      <main className="flex flex-col mt-8 gap-[32px] row-start-2 items-center sm:items-start w-200">
        When talking about Danish deserts, there's only two real contenders for THE EPIC CAKE BATTLES OF HISTORY.
        <br />
        <br />
        In the right corner we have the Brunner, it's spongy, it's greasy and above else it has an incredibly sweet and delicious dark caramelization!
        If you've never had a taste of this beast of a cake, the best way to describe it is as a greasy sugarcoated bun!
        <br />
        <br />
        In the left corner we have the Othello, it's flavour rich, it's a classic and it's the previous heavy weight champion! The Othello is deliciousness incarnated and every bite tastes like a piece of heaven.
        <br />
        THIS IS GOING TO BE CLOSE!
        <br />
        <br />
        If you manage to find out who the champion is, click this button!
        <button className="font-bold py-2 px-4 rounded border">
          <Link onClick={() => setShowError(true)} href={"/admin"}>
            Click here!
          </Link>
        </button>
        {showError && (
          <span className="text-red-500 ml-2">I don't think you've found the correct champion.</span>)
        }
      </main>
      <footer className="row-start-3 flex gap-[24px] flex-wrap items-center justify-center">

      </footer>
    </div>
  );
}
