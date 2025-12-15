declare module '@stripe/stripe-js' {
  export interface Stripe {
    redirectToCheckout(options: {
      sessionId: string;
    }): Promise<{ error?: { message: string } }>;
  }
  
  export function loadStripe(
    publishableKey: string,
    options?: { stripeAccount?: string; locale?: string }
  ): Promise<Stripe | null>;
}
