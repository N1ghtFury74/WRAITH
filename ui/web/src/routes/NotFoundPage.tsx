import { Link } from "react-router-dom";

import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/states";

export function NotFoundPage() {
  return (
    <div className="p-6">
      <EmptyState
        title="Page not found"
        hint="That route does not exist in WRAITH."
        action={
          <Button asChild size="sm" variant="secondary">
            <Link to="/cases">Go to cases</Link>
          </Button>
        }
      />
    </div>
  );
}
