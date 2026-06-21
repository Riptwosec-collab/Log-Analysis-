"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

type Review = {
  id: string;
  name: string;
  role: string;
  rating: number;
  comment: string;
  tags: string[];
  timestamp: string;
};

const ROLE_OPTIONS = [
  "SOC Analyst", "Security Engineer", "IT Admin",
  "Incident Responder", "Threat Hunter", "Manager / CISO", "Other",
];

const TAG_OPTIONS = [
  "Easy to use", "Accurate results", "Fast analysis",
  "Great visualizations", "Useful exports", "Good for training",
  "Missing features", "Needs improvement",
];

const DEMO_REVIEWS: Review[] = [
  {
    id: "demo1",
    name: "Tanakorn S.",
    role: "SOC Analyst",
    rating: 5,
    comment: "ใช้งานง่ายมาก วิเคราะห์ log ได้ครอบคลุม ชอบ MITRE ATT&CK matrix และ World Map มากครับ",
    tags: ["Easy to use", "Accurate results", "Great visualizations"],
    timestamp: "2026-06-15T09:30:00Z",
  },
  {
    id: "demo2",
    name: "Priya M.",
    role: "Security Engineer",
    rating: 4,
    comment: "Very comprehensive for multi-vendor log parsing. The custom rules editor is a huge plus for our team.",
    tags: ["Accurate results", "Useful exports", "Fast analysis"],
    timestamp: "2026-06-17T14:22:00Z",
  },
  {
    id: "demo3",
    name: "Weerachai P.",
    role: "IT Admin",
    rating: 5,
    comment: "Webhook + Slack integration ดีมาก ตอนนี้ทีมได้รับ alert ทันทีที่มี critical finding",
    tags: ["Easy to use", "Fast analysis", "Good for training"],
    timestamp: "2026-06-18T11:05:00Z",
  },
];

function StarRating({ value, onChange, readonly = false }: { value: number; onChange?: (v: number) => void; readonly?: boolean }) {
  const [hover, setHover] = useState(0);
  return (
    <div className="flex gap-1">
      {[1, 2, 3, 4, 5].map((star) => (
        <button
          key={star}
          type="button"
          disabled={readonly}
          onClick={() => onChange?.(star)}
          onMouseEnter={() => !readonly && setHover(star)}
          onMouseLeave={() => !readonly && setHover(0)}
          className={`text-3xl transition-transform ${readonly ? "cursor-default" : "cursor-pointer hover:scale-125"}`}
          style={{ color: star <= (hover || value) ? "#f59e0b" : "#3f3f46", textShadow: star <= (hover || value) ? "0 0 8px rgba(245,158,11,0.5)" : "none" }}
        >
          ★
        </button>
      ))}
    </div>
  );
}

function RatingLabel({ rating }: { rating: number }) {
  const labels: Record<number, { text: string; color: string }> = {
    1: { text: "Poor", color: "#ef4444" },
    2: { text: "Fair", color: "#f97316" },
    3: { text: "Good", color: "#eab308" },
    4: { text: "Great", color: "#22c55e" },
    5: { text: "Excellent!", color: "#06b6d4" },
  };
  if (!rating) return null;
  const l = labels[rating];
  return (
    <span className="text-sm font-semibold" style={{ color: l.color }}>
      {l.text}
    </span>
  );
}

function ReviewCard({ review }: { review: Review }) {
  const date = new Date(review.timestamp).toLocaleDateString("th-TH", {
    year: "numeric", month: "short", day: "numeric",
  });
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 card-3d">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-cyan-500/20 text-lg font-bold text-cyan-300">
            {review.name.charAt(0)}
          </div>
          <div>
            <p className="font-semibold text-white">{review.name}</p>
            <p className="text-xs text-zinc-500">{review.role} · {date}</p>
          </div>
        </div>
        <StarRating value={review.rating} readonly />
      </div>
      <p className="mt-4 text-sm leading-6 text-zinc-300">{review.comment}</p>
      {review.tags.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-2">
          {review.tags.map((tag) => (
            <span key={tag} className="rounded-full border border-zinc-700 bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">
              {tag}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function StatsBar({ reviews }: { reviews: Review[] }) {
  if (!reviews.length) return null;
  const avg = reviews.reduce((s, r) => s + r.rating, 0) / reviews.length;
  const counts = [5, 4, 3, 2, 1].map((star) => ({
    star,
    count: reviews.filter((r) => r.rating === star).length,
  }));
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 card-3d">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:gap-8">
        <div className="text-center">
          <p className="text-5xl font-bold text-white">{avg.toFixed(1)}</p>
          <StarRating value={Math.round(avg)} readonly />
          <p className="mt-1 text-xs text-zinc-500">{reviews.length} review{reviews.length !== 1 ? "s" : ""}</p>
        </div>
        <div className="flex-1 space-y-1.5">
          {counts.map(({ star, count }) => (
            <div key={star} className="flex items-center gap-2 text-xs text-zinc-400">
              <span className="w-3">{star}</span>
              <span className="text-amber-400">★</span>
              <div className="flex-1 h-2 rounded-full bg-zinc-800">
                <div
                  className="h-2 rounded-full bg-amber-400 transition-all duration-700"
                  style={{ width: reviews.length ? `${(count / reviews.length) * 100}%` : "0%" }}
                />
              </div>
              <span className="w-4 text-right">{count}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function ReviewPage() {
  const router = useRouter();
  const [reviews, setReviews] = useState<Review[]>(DEMO_REVIEWS);
  const [name, setName] = useState("");
  const [role, setRole] = useState(ROLE_OPTIONS[0]);
  const [rating, setRating] = useState(0);
  const [comment, setComment] = useState("");
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const saved = localStorage.getItem("soc_reviews");
    if (saved) {
      try {
        const parsed: Review[] = JSON.parse(saved);
        setReviews([...DEMO_REVIEWS, ...parsed]);
      } catch {}
    }
  }, []);

  function toggleTag(tag: string) {
    setSelectedTags((prev) =>
      prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!rating) { setError("Please select a star rating."); return; }
    if (!name.trim()) { setError("Please enter your name."); return; }
    if (!comment.trim()) { setError("Please write a comment."); return; }

    const newReview: Review = {
      id: Date.now().toString(),
      name: name.trim(),
      role,
      rating,
      comment: comment.trim(),
      tags: selectedTags,
      timestamp: new Date().toISOString(),
    };

    const saved = localStorage.getItem("soc_reviews");
    const existing: Review[] = saved ? JSON.parse(saved) : [];
    const updated = [newReview, ...existing];
    localStorage.setItem("soc_reviews", JSON.stringify(updated));
    setReviews([...DEMO_REVIEWS, ...updated]);
    setSubmitted(true);
    setError("");
  }

  return (
    <main className="min-h-screen bg-zinc-950 text-zinc-100" style={{ backgroundColor: "var(--bg-primary)", color: "var(--text-primary)" }}>
      <div className="mx-auto max-w-4xl px-4 py-10 sm:px-6">

        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-cyan-300">SOC Dashboard</p>
            <h1 className="mt-1 text-3xl font-semibold text-white">User Reviews</h1>
            <p className="mt-1 text-sm text-zinc-400">Share your experience with the Log Analysis Dashboard</p>
          </div>
          <button
            onClick={() => router.push("/")}
            className="rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:border-cyan-500 hover:text-white"
          >
            ← Back to Dashboard
          </button>
        </div>

        {/* Stats */}
        <div className="mb-6">
          <StatsBar reviews={reviews} />
        </div>

        {/* Review Form */}
        {!submitted ? (
          <div className="mb-8 rounded-xl border border-cyan-900/50 bg-zinc-900 p-6 card-3d">
            <h2 className="mb-5 text-lg font-semibold text-white">Write a Review</h2>
            <form onSubmit={handleSubmit} className="space-y-5">

              {/* Rating */}
              <div>
                <label className="mb-2 block text-sm font-medium text-zinc-300">Overall Rating *</label>
                <div className="flex items-center gap-3">
                  <StarRating value={rating} onChange={setRating} />
                  <RatingLabel rating={rating} />
                </div>
              </div>

              {/* Name + Role */}
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-1.5 block text-sm font-medium text-zinc-300">Your Name *</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Tanakorn S."
                    className="w-full rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm text-zinc-200 outline-none ring-cyan-500 focus:ring-2 placeholder:text-zinc-600"
                  />
                </div>
                <div>
                  <label className="mb-1.5 block text-sm font-medium text-zinc-300">Your Role</label>
                  <select
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    className="w-full rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm text-zinc-200 outline-none hover:border-cyan-500"
                  >
                    {ROLE_OPTIONS.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </div>
              </div>

              {/* Comment */}
              <div>
                <label className="mb-1.5 block text-sm font-medium text-zinc-300">Your Review *</label>
                <textarea
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  rows={4}
                  placeholder="Tell us what you think about the SOC Dashboard..."
                  className="w-full resize-none rounded-md border border-zinc-700 bg-black px-3 py-2 text-sm text-zinc-200 outline-none ring-cyan-500 focus:ring-2 placeholder:text-zinc-600"
                />
              </div>

              {/* Tags */}
              <div>
                <label className="mb-2 block text-sm font-medium text-zinc-300">Tags (optional)</label>
                <div className="flex flex-wrap gap-2">
                  {TAG_OPTIONS.map((tag) => (
                    <button
                      key={tag}
                      type="button"
                      onClick={() => toggleTag(tag)}
                      className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                        selectedTags.includes(tag)
                          ? "border-cyan-500 bg-cyan-500/15 text-cyan-200"
                          : "border-zinc-700 text-zinc-400 hover:border-zinc-500"
                      }`}
                    >
                      {selectedTags.includes(tag) ? "✓ " : ""}{tag}
                    </button>
                  ))}
                </div>
              </div>

              {error && (
                <p className="rounded-md border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-red-300">{error}</p>
              )}

              <button
                type="submit"
                className="btn-3d rounded-md bg-cyan-500 px-6 py-2.5 text-sm font-semibold text-zinc-950 hover:bg-cyan-400"
              >
                Submit Review
              </button>
            </form>
          </div>
        ) : (
          <div className="mb-8 rounded-xl border border-green-800 bg-green-950/40 p-6 text-center card-3d">
            <p className="text-4xl">🎉</p>
            <h2 className="mt-3 text-xl font-semibold text-green-300">Thank you for your review!</h2>
            <p className="mt-1 text-sm text-zinc-400">Your feedback helps improve the SOC Dashboard.</p>
            <button
              onClick={() => { setSubmitted(false); setRating(0); setName(""); setComment(""); setSelectedTags([]); }}
              className="mt-4 rounded-md border border-zinc-700 px-4 py-2 text-sm text-zinc-300 hover:border-cyan-500"
            >
              Write another review
            </button>
          </div>
        )}

        {/* Reviews list */}
        <div>
          <h2 className="mb-4 text-lg font-semibold text-white">All Reviews ({reviews.length})</h2>
          <div className="space-y-4">
            {reviews.map((review) => (
              <ReviewCard key={review.id} review={review} />
            ))}
          </div>
        </div>

      </div>
    </main>
  );
}
