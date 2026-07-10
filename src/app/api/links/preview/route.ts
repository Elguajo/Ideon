import { NextResponse } from "next/server";
import { fetchLinkMetadata } from "@lib/services/metadata";
import { getAuthUser } from "@auth";

export async function POST(req: Request) {
  try {
    const user = await getAuthUser();
    if (!user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { url } = await req.json();

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 });
    }

    const metadata = await fetchLinkMetadata(url);

    return NextResponse.json({
      title: metadata.title,
      description: metadata.description,
      image: metadata.image,
    });
  } catch {
    // Silence 429/403/500 errors to prevent frontend retries and console noise
    return NextResponse.json({
      title: "",
      description: "",
      image: "",
    });
  }
}
